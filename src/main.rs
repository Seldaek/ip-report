use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Terminal,
};
use regex::Regex;
use rusqlite::{params, Connection};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Write, stdout, stderr},
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, PartialEq)]
enum GroupBy {
    Ip,
    Org,
    UserAgent,
}

impl GroupBy {
    fn next(self) -> Self {
        match self {
            GroupBy::Ip => GroupBy::Org,
            GroupBy::Org => GroupBy::UserAgent,
            GroupBy::UserAgent => GroupBy::Ip,
        }
    }
    
    fn label(self) -> &'static str {
        match self {
            GroupBy::Ip => "IP",
            GroupBy::Org => "Org",
            GroupBy::UserAgent => "UA",
        }
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{}…", truncated)
    }
}

#[derive(Parser)]
#[command(name = "ip-report", version, about = "Analyze IP addresses from log files")]
struct Args {
    /// Input file to parse
    file: PathBuf,
    /// Show only top N IPs (e.g., "10" or "10%")
    #[arg(long)]
    top: Option<String>,
    /// Minimum occurrence count
    #[arg(long)]
    min: Option<u64>,
    /// SQLite database path
    #[arg(long, default_value = "ip-report.db")]
    db: PathBuf,
    /// Max concurrent lookups
    #[arg(long, default_value = "20")]
    concurrency: usize,
    /// Skip DNS/whois lookups, only show counts
    #[arg(long)]
    no_lookup: bool,
    /// Filter lines by regex (matches whole line)
    #[arg(long)]
    filter: Option<String>,
    /// Filter lines by user agent regex
    #[arg(long)]
    ua_filter: Option<String>,
    /// Field delimiter (enables fast field-based parsing)
    #[arg(long)]
    delimiter: Option<String>,
    /// 1-indexed field number for IP (requires --delimiter)
    #[arg(long)]
    ip_field: Option<usize>,
    /// 1-indexed field number for user agent (requires --delimiter)
    #[arg(long)]
    ua_field: Option<usize>,
}

#[derive(Clone)]
struct IpRecord {
    ip: String,
    count: u64,
    user_agent: Option<String>,
    reverse_dns: Option<String>,
    org: Option<String>,
    looked_up: bool,
    lookup_in_progress: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    if args.top.is_some() && args.min.is_some() {
        anyhow::bail!("Cannot use both --top and --min together");
    }
    
    let (ip_counts, total_lines) = parse_file(
        &args.file,
        args.filter.as_deref(),
        args.ua_filter.as_deref(),
        args.delimiter.as_deref(),
        args.ip_field,
        args.ua_field,
    )?;
    let total_ips = ip_counts.len();
    let filtered = apply_filters(ip_counts, args.top.as_deref(), args.min);
    let filter_desc = if let Some(ref top) = args.top {
        format!("top {} of {}", top, total_ips)
    } else if let Some(min) = args.min {
        format!("min {} of {}", min, total_ips)
    } else {
        format!("{}", total_ips)
    };
    
    if filtered.is_empty() {
        eprintln!("No IPs match the criteria");
        return Ok(());
    }
    
    if args.no_lookup {
        println!("Total lines: {}\n", total_lines);
        println!("{:<8} {:<6} {:<45} {}", "Count", "%", "IP", "User Agent");
        println!("{}", "-".repeat(110));
        for (ip, count, _is_v6, ua) in &filtered {
            let pct = if total_lines > 0 { (*count as f64 / total_lines as f64) * 100.0 } else { 0.0 };
            println!(
                "{:<8} {:<6.2} {:<45} {}",
                count,
                pct,
                ip,
                ua.as_deref().unwrap_or("-")
            );
        }
        return Ok(());
    }
    
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_lookups_and_display(filtered, &args.db, args.concurrency, total_lines, &filter_desc))?;
    
    Ok(())
}

fn parse_file(
    path: &PathBuf,
    filter: Option<&str>,
    ua_filter: Option<&str>,
    delimiter: Option<&str>,
    ip_field: Option<usize>,
    ua_field: Option<usize>,
) -> Result<(HashMap<String, (u64, bool, Option<String>)>, u64)> {
    let file = File::open(path).context("Failed to open input file")?;
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    
    let filter_re = filter.map(|p| Regex::new(p)).transpose()
        .context("Invalid --filter regex")?;
    let ua_filter_re = ua_filter.map(|p| Regex::new(p)).transpose()
        .context("Invalid --ua-filter regex")?;
    
    // Only compile regex if not using delimiter mode
    let ipv4_re = if delimiter.is_none() {
        Some(Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")?)
    } else {
        None
    };
    let ipv6_re = if delimiter.is_none() {
        Some(Regex::new(r"\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)\b")?)
    } else {
        None
    };
    
    // Track (count, is_v6, ua_counts)
    let mut counts: HashMap<String, (u64, bool, HashMap<String, u64>)> = HashMap::new();
    let mut total_lines: u64 = 0;
    let mut bytes_read: u64 = 0;
    let mut last_progress: u64 = 0;
    let mut line = String::new();
    
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        bytes_read += n as u64;
        
        if bytes_read - last_progress > 10_000_000 {
            last_progress = bytes_read;
            if file_size > 0 {
                eprint!("\rReading: {}% ({} lines)", bytes_read * 100 / file_size, total_lines);
            } else {
                eprint!("\rReading: {} bytes ({} lines)", bytes_read, total_lines);
            }
            stderr().flush().ok();
        }
        
        let line = line.trim_end();
        
        if let Some(ref re) = filter_re {
            if !re.is_match(line) {
                continue;
            }
        }
        
        let (ip_str, user_agent) = if let Some(delim) = delimiter {
            let fields: Vec<&str> = line.split(delim).collect();
            
            let ip = if let Some(idx) = ip_field {
                fields.get(idx.saturating_sub(1)).map(|s| *s)
            } else {
                fields.iter().find(|f| f.parse::<IpAddr>().is_ok()).map(|s| *s)
            };
            
            let ua = if let Some(idx) = ua_field {
                fields.get(idx.saturating_sub(1)).filter(|s| !s.is_empty()).map(|s| s.to_string())
            } else {
                fields.iter().rev().find(|f| !f.is_empty()).map(|s| s.to_string())
            };
            
            (ip.map(|s| s.to_string()), ua)
        } else {
            let ua = if let Some(last_quote) = line.rfind('"') {
                line[..last_quote].rfind('"').map(|start| line[start + 1..last_quote].to_string())
            } else {
                None
            };
            (None, ua)
        };
        
        if let Some(ref re) = ua_filter_re {
            match &user_agent {
                Some(ua) if re.is_match(ua) => {}
                _ => continue,
            }
        }
        
        total_lines += 1;
        
        let mut record_hit = |ip: IpAddr, ua: Option<String>| {
            let key = ip.to_string();
            let is_v6 = ip.is_ipv6();
            let entry = counts.entry(key).or_insert((0, is_v6, HashMap::new()));
            entry.0 += 1;
            if let Some(ua_str) = ua {
                *entry.2.entry(ua_str).or_insert(0) += 1;
            }
        };
        
        if let Some(ref ip_s) = ip_str {
            if let Ok(ip) = ip_s.parse::<IpAddr>() {
                record_hit(ip, user_agent);
                continue;
            }
        }
        
        if delimiter.is_some() {
            continue;
        }
        
        // Fast path: first word is IP
        if let Some(first_word) = line.split_whitespace().next() {
            if let Ok(ip) = first_word.parse::<IpAddr>() {
                record_hit(ip, user_agent);
                continue;
            }
        }
        
        if let Some(ref re) = ipv4_re {
            if let Some(cap) = re.captures(line) {
                if let Some(m) = cap.get(1) {
                    if let Ok(ip) = m.as_str().parse::<IpAddr>() {
                        record_hit(ip, user_agent);
                        continue;
                    }
                }
            }
        }
        
        if let Some(ref re) = ipv6_re {
            if let Some(cap) = re.captures(line) {
                if let Some(m) = cap.get(1) {
                    if let Ok(ip) = m.as_str().parse::<IpAddr>() {
                        record_hit(ip, user_agent);
                    }
                }
            }
        }
    }
    
    if last_progress > 0 {
        eprintln!("\rReading: done ({} lines)        ", total_lines);
    }
    
    // Convert to final format with most common UA
    let result: HashMap<String, (u64, bool, Option<String>)> = counts
        .into_iter()
        .map(|(ip, (count, is_v6, ua_counts))| {
            let top_ua = ua_counts
                .into_iter()
                .max_by_key(|(_, c)| *c)
                .map(|(ua, _)| ua);
            (ip, (count, is_v6, top_ua))
        })
        .collect();
    
    Ok((result, total_lines))
}

fn apply_filters(
    counts: HashMap<String, (u64, bool, Option<String>)>,
    top: Option<&str>,
    min: Option<u64>,
) -> Vec<(String, u64, bool, Option<String>)> {
    let mut sorted: Vec<_> = counts.into_iter()
        .map(|(ip, (c, v6, ua))| (ip, c, v6, ua))
        .collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    
    if let Some(top_str) = top {
        let limit = if top_str.ends_with('%') {
            let pct: f64 = top_str.trim_end_matches('%').parse().unwrap_or(100.0);
            ((sorted.len() as f64 * pct / 100.0).ceil() as usize).max(1)
        } else {
            top_str.parse().unwrap_or(sorted.len())
        };
        sorted.truncate(limit);
    }
    
    if let Some(min_count) = min {
        sorted.retain(|(_, c, _, _)| *c >= min_count);
    }
    
    sorted
}

async fn run_lookups_and_display(
    ips: Vec<(String, u64, bool, Option<String>)>,
    db_path: &PathBuf,
    concurrency: usize,
    total_lines: u64,
    filter_desc: &str,
) -> Result<()> {
    let conn = Connection::open(db_path)?;
    init_db(&conn)?;
    
    let records: Vec<IpRecord> = ips.iter().map(|(ip, count, is_v6, ua)| {
        let existing = get_ip_record(&conn, ip);
        if let Some(rec) = existing {
            IpRecord {
                ip: ip.clone(),
                count: *count,
                user_agent: ua.clone().or(rec.2),
                reverse_dns: rec.3,
                org: rec.4,
                looked_up: rec.5,
                lookup_in_progress: false,
            }
        } else {
            insert_ip(&conn, ip, *is_v6, ua.as_deref()).ok();
            IpRecord {
                ip: ip.clone(),
                count: *count,
                user_agent: ua.clone(),
                reverse_dns: None,
                org: None,
                looked_up: false,
                lookup_in_progress: false,
            }
        }
    }).collect();
    
    let records = Arc::new(Mutex::new(records));
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let db_path = db_path.clone();
    
    let indices_to_lookup: Vec<(usize, String)> = {
        let recs = records.lock().unwrap();
        recs.iter()
            .enumerate()
            .filter(|(_, rec)| !rec.looked_up)
            .map(|(idx, rec)| (idx, rec.ip.clone()))
            .collect()
    };
    
    let mut handles = vec![];
    for (idx, ip) in indices_to_lookup {
        let sem = semaphore.clone();
        let recs = records.clone();
        let dbp = db_path.clone();
        
        recs.lock().unwrap()[idx].lookup_in_progress = true;
        
        let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let (rdns, org) = perform_lookup(&ip).await;
                
                {
                    let mut recs = recs.lock().unwrap();
                    recs[idx].reverse_dns = rdns.clone();
                    recs[idx].org = org.clone();
                    recs[idx].looked_up = true;
                    recs[idx].lookup_in_progress = false;
                }
                
                if let Ok(conn) = Connection::open(&dbp) {
                    update_ip_lookup(&conn, &ip, rdns.as_deref(), org.as_deref()).ok();
                }
            });
            handles.push(handle);
        }
    
    let is_tty = atty::is(atty::Stream::Stdout);
    
    if is_tty {
        run_tui(records.clone(), handles, total_lines, filter_desc).await?;
    } else {
        for h in handles {
            h.await.ok();
        }
        let recs = records.lock().unwrap();
        println!("Total lines: {}\n", total_lines);
        println!("{:<8} {:<6} {:<40} {:<40} {:<30} {}", "Count", "%", "IP", "Reverse DNS", "Org", "User Agent");
        println!("{}", "-".repeat(170));
        for rec in recs.iter() {
            let pct = if total_lines > 0 { (rec.count as f64 / total_lines as f64) * 100.0 } else { 0.0 };
            println!(
                "{:<8} {:<6.2} {:<40} {:<40} {:<30} {}",
                rec.count,
                pct,
                rec.ip,
                truncate_str(rec.reverse_dns.as_deref().unwrap_or("-"), 38),
                truncate_str(rec.org.as_deref().unwrap_or("-"), 28),
                truncate_str(rec.user_agent.as_deref().unwrap_or("-"), 50)
            );
        }
    }
    
    Ok(())
}

async fn run_tui(
    records: Arc<Mutex<Vec<IpRecord>>>,
    handles: Vec<tokio::task::JoinHandle<()>>,
    total_lines: u64,
    filter_desc: &str,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    let mut table_state = TableState::default();
    table_state.select(Some(0));
    let mut group_by = GroupBy::Ip;
    let mut show_rdns = true;
    let mut show_ua = true;
    let mut show_org = true;
    let mut search_mode = false;
    let mut search_query = String::new();
    
    let pending_count = Arc::new(Mutex::new(handles.len()));
    for h in handles {
        let pc = pending_count.clone();
        tokio::spawn(async move {
            h.await.ok();
            *pc.lock().unwrap() -= 1;
        });
    }
    
    loop {
        let recs = records.lock().unwrap().clone();
        let pending = *pending_count.lock().unwrap();
        
        terminal.draw(|f| {
            let filtered_recs: Vec<IpRecord> = if search_query.is_empty() {
                recs.clone()
            } else {
                let q = search_query.to_lowercase();
                recs.iter().filter(|r| {
                    r.ip.to_lowercase().contains(&q)
                        || r.reverse_dns.as_ref().map(|s| s.to_lowercase().contains(&q)).unwrap_or(false)
                        || r.org.as_ref().map(|s| s.to_lowercase().contains(&q)).unwrap_or(false)
                        || r.user_agent.as_ref().map(|s| s.to_lowercase().contains(&q)).unwrap_or(false)
                }).cloned().collect()
            };
            
            let search_str = if search_mode {
                format!(" [SEARCH: {}█]", search_query)
            } else if !search_query.is_empty() {
                format!(" [filter: {}]", search_query)
            } else {
                String::new()
            };
            
            match group_by {
                GroupBy::Ip => render_ip_view(f, &filtered_recs, &mut table_state, total_lines, pending, show_rdns, show_ua, show_org, filter_desc, group_by, &search_str),
                GroupBy::Org => render_grouped_view(f, &filtered_recs, &mut table_state, total_lines, pending, filter_desc, "Org", group_by, &search_str, |r| r.org.clone().unwrap_or_else(|| "-".to_string())),
                GroupBy::UserAgent => render_grouped_view(f, &filtered_recs, &mut table_state, total_lines, pending, filter_desc, "User Agent", group_by, &search_str, |r| r.user_agent.clone().unwrap_or_else(|| "-".to_string())),
            }
        })?;
        
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if search_mode {
                        match key.code {
                            KeyCode::Esc => {
                                search_mode = false;
                                search_query.clear();
                                table_state.select(Some(0));
                            }
                            KeyCode::Enter => {
                                search_mode = false;
                                table_state.select(Some(0));
                            }
                            KeyCode::Backspace => {
                                search_query.pop();
                                table_state.select(Some(0));
                            }
                            KeyCode::Char(c) => {
                                search_query.push(c);
                                table_state.select(Some(0));
                            }
                            _ => {}
                        }
                        continue;
                    }
                    
                    let filtered_recs: Vec<&IpRecord> = if search_query.is_empty() {
                        recs.iter().collect()
                    } else {
                        let q = search_query.to_lowercase();
                        recs.iter().filter(|r| {
                            r.ip.to_lowercase().contains(&q)
                                || r.reverse_dns.as_ref().map(|s| s.to_lowercase().contains(&q)).unwrap_or(false)
                                || r.org.as_ref().map(|s| s.to_lowercase().contains(&q)).unwrap_or(false)
                                || r.user_agent.as_ref().map(|s| s.to_lowercase().contains(&q)).unwrap_or(false)
                        }).collect()
                    };
                    
                    let len = match group_by {
                        GroupBy::Ip => filtered_recs.len(),
                        GroupBy::Org => aggregate_by_field(&filtered_recs.iter().map(|r| (*r).clone()).collect::<Vec<_>>(), |r| r.org.clone().unwrap_or_else(|| "-".to_string())).len(),
                        GroupBy::UserAgent => aggregate_by_field(&filtered_recs.iter().map(|r| (*r).clone()).collect::<Vec<_>>(), |r| r.user_agent.clone().unwrap_or_else(|| "-".to_string())).len(),
                    };
                    
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('s') | KeyCode::Char('/') => {
                            search_mode = true;
                        }
                        KeyCode::Char('g') => {
                            group_by = group_by.next();
                            table_state.select(Some(0));
                        }
                        KeyCode::Char('r') => show_rdns = !show_rdns,
                        KeyCode::Char('u') => show_ua = !show_ua,
                        KeyCode::Char('o') => show_org = !show_org,
                        KeyCode::Down | KeyCode::Char('j') => {
                            let i = table_state.selected().unwrap_or(0);
                            table_state.select(Some((i + 1).min(len.saturating_sub(1))));
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            let i = table_state.selected().unwrap_or(0);
                            table_state.select(Some(i.saturating_sub(1)));
                        }
                        KeyCode::PageDown => {
                            let i = table_state.selected().unwrap_or(0);
                            table_state.select(Some((i + 20).min(len.saturating_sub(1))));
                        }
                        KeyCode::PageUp => {
                            let i = table_state.selected().unwrap_or(0);
                            table_state.select(Some(i.saturating_sub(20)));
                        }
                        KeyCode::Home => table_state.select(Some(0)),
                        KeyCode::End => table_state.select(Some(len.saturating_sub(1))),
                        _ => {}
                    }
                }
            }
        }
    }
    
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    
    Ok(())
}

fn aggregate_by_field<F>(recs: &[IpRecord], key_fn: F) -> Vec<(String, u64, usize)>
where
    F: Fn(&IpRecord) -> String,
{
    let mut groups: HashMap<String, (u64, usize)> = HashMap::new();
    for rec in recs {
        let key = key_fn(rec);
        let entry = groups.entry(key).or_insert((0, 0));
        entry.0 += rec.count;
        entry.1 += 1;
    }
    let mut sorted: Vec<_> = groups.into_iter().map(|(k, (count, n))| (k, count, n)).collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    sorted
}

fn render_ip_view(
    f: &mut ratatui::Frame,
    recs: &[IpRecord],
    table_state: &mut TableState,
    total_lines: u64,
    pending: usize,
    show_rdns: bool,
    show_ua: bool,
    show_org: bool,
    filter_desc: &str,
    group_by: GroupBy,
    search_str: &str,
) {
    let mut header_cells = vec![
        Cell::from("Count"),
        Cell::from("%"),
        Cell::from("IP"),
    ];
    if show_rdns { header_cells.push(Cell::from("Reverse DNS")); }
    if show_org { header_cells.push(Cell::from("Org")); }
    if show_ua { header_cells.push(Cell::from("User Agent")); }
    
    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));
    
    let visible_cols = 3 + show_rdns as usize + show_ua as usize + show_org as usize;
    let extra_width: usize = if visible_cols <= 4 { 60 } else if visible_cols == 5 { 30 } else { 0 };
    
    let rows: Vec<Row> = recs.iter().map(|rec| {
        let status = if rec.lookup_in_progress { "⏳" } else { "" };
        let pct = if total_lines > 0 { (rec.count as f64 / total_lines as f64) * 100.0 } else { 0.0 };
        let mut cells = vec![
            Cell::from(format!("{}{}", rec.count, status)),
            Cell::from(format!("{:.2}", pct)),
            Cell::from(rec.ip.clone()),
        ];
        if show_rdns {
            cells.push(Cell::from(truncate_str(rec.reverse_dns.as_deref().unwrap_or("-"), 38 + extra_width)));
        }
        if show_org {
            cells.push(Cell::from(truncate_str(rec.org.as_deref().unwrap_or("-"), 25 + extra_width)));
        }
        if show_ua {
            cells.push(Cell::from(truncate_str(rec.user_agent.as_deref().unwrap_or("-"), 40 + extra_width)));
        }
        Row::new(cells)
    }).collect();
    
    let mut widths = vec![
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(40),
    ];
    if show_rdns { widths.push(Constraint::Length((40 + extra_width) as u16)); }
    if show_org { widths.push(Constraint::Length((27 + extra_width) as u16)); }
    if show_ua { widths.push(Constraint::Min(20)); }
    
    let toggles = format!("r:{} u:{} o:{}",
        if show_rdns { "on" } else { "off" },
        if show_ua { "on" } else { "off" },
        if show_org { "on" } else { "off" },
    );
    
    let pending_str = if pending > 0 { format!(", {} pending", pending) } else { String::new() };
    
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {} IPs, {} lines{} [{}] [by:{}]{} (g/r/u/o/s, q=quit) ",
            filter_desc, total_lines, pending_str, toggles, group_by.label(), search_str
        )))
        .row_highlight_style(Style::default().bg(Color::DarkGray));
    
    f.render_stateful_widget(table, f.area(), table_state);
}

fn render_grouped_view<F>(
    f: &mut ratatui::Frame,
    recs: &[IpRecord],
    table_state: &mut TableState,
    total_lines: u64,
    pending: usize,
    filter_desc: &str,
    group_label: &str,
    group_by: GroupBy,
    search_str: &str,
    key_fn: F,
)
where
    F: Fn(&IpRecord) -> String,
{
    let groups = aggregate_by_field(recs, key_fn);
    
    let header = Row::new(vec![
        Cell::from("Count"),
        Cell::from("%"),
        Cell::from("IPs"),
        Cell::from(group_label),
    ]).style(Style::default().add_modifier(Modifier::BOLD));
    
    let rows: Vec<Row> = groups.iter().map(|(key, count, ip_count)| {
        let pct = if total_lines > 0 { (*count as f64 / total_lines as f64) * 100.0 } else { 0.0 };
        Row::new(vec![
            Cell::from(format!("{}", count)),
            Cell::from(format!("{:.2}", pct)),
            Cell::from(format!("{}", ip_count)),
            Cell::from(key.clone()),
        ])
    }).collect();
    
    let widths = [
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Min(40),
    ];
    
    let pending_str = if pending > 0 { format!(", {} pending", pending) } else { String::new() };
    
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {} IPs by {}, {} lines{} [by:{}]{} (g/s, q=quit) ",
            filter_desc, group_label, total_lines, pending_str, group_by.label(), search_str
        )))
        .row_highlight_style(Style::default().bg(Color::DarkGray));
    
    f.render_stateful_widget(table, f.area(), table_state);
}

async fn perform_lookup(ip: &str) -> (Option<String>, Option<String>) {
    let ip_clone = ip.to_string();
    
    let rdns = tokio::task::spawn_blocking(move || {
        if let Ok(addr) = ip_clone.parse::<IpAddr>() {
            dns_lookup::lookup_addr(&addr).ok()
        } else {
            None
        }
    }).await.ok().flatten();
    
    let org = tokio::process::Command::new("whois")
        .arg(ip)
        .output()
        .await
        .ok()
        .and_then(|out| {
            let text = String::from_utf8_lossy(&out.stdout);
            extract_org_from_whois(&text)
        });
    
    (rdns, org)
}

fn extract_org_from_whois(text: &str) -> Option<String> {
    let patterns = [
        r"(?i)^OrgName:\s*(.+)$",
        r"(?i)^org-name:\s*(.+)$",
        r"(?i)^Organization:\s*(.+)$",
        r"(?i)^descr:\s*(.+)$",
        r"(?i)^netname:\s*(.+)$",
    ];
    
    for pat in patterns {
        if let Ok(re) = Regex::new(pat) {
            for line in text.lines() {
                if let Some(cap) = re.captures(line) {
                    if let Some(m) = cap.get(1) {
                        let val = m.as_str().trim();
                        if !val.is_empty() {
                            return Some(val.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn init_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ips (
            ip TEXT PRIMARY KEY,
            is_v6 INTEGER NOT NULL,
            looked_up INTEGER NOT NULL DEFAULT 0,
            reverse_dns TEXT,
            org TEXT,
            user_agent TEXT,
            insert_date TEXT NOT NULL
        )",
        [],
    )?;
    Ok(())
}

fn get_ip_record(conn: &Connection, ip: &str) -> Option<(String, bool, Option<String>, Option<String>, Option<String>, bool)> {
    conn.query_row(
        "SELECT ip, is_v6, user_agent, reverse_dns, org, looked_up FROM ips WHERE ip = ?",
        [ip],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i32>(1)? != 0,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i32>(5)? != 0,
            ))
        },
    ).ok()
}

fn insert_ip(conn: &Connection, ip: &str, is_v6: bool, user_agent: Option<&str>) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR IGNORE INTO ips (ip, is_v6, user_agent, insert_date) VALUES (?, ?, ?, ?)",
        params![ip, is_v6 as i32, user_agent, now],
    )?;
    if let Some(ua) = user_agent {
        conn.execute(
            "UPDATE ips SET user_agent = ? WHERE ip = ?",
            params![ua, ip],
        )?;
    }
    Ok(())
}

fn update_ip_lookup(conn: &Connection, ip: &str, rdns: Option<&str>, org: Option<&str>) -> Result<()> {
    conn.execute(
        "UPDATE ips SET looked_up = 1, reverse_dns = ?, org = ? WHERE ip = ?",
        params![rdns, org, ip],
    )?;
    Ok(())
}
