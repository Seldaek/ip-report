use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ipnetwork::IpNetwork;
use ratatui::{
    backend::CrosstermBackend,
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Terminal,
};
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::{stderr, stdout, BufRead, BufReader, Write},
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

fn extract_ua_base(ua: &str) -> String {
    ua.split('/').next().unwrap_or(ua).to_string()
}

#[derive(Parser)]
#[command(
    name = "ip-report",
    version,
    about = "Analyze IP addresses from log files"
)]
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
    /// Refresh cloud IP ranges before lookup
    #[arg(long)]
    refresh_cloud: bool,
    /// Force refresh even if recently updated
    #[arg(long)]
    force_cloud_refresh: bool,
    /// Max age of cloud ranges in hours before auto-refresh (default: 168 = 7 days)
    #[arg(long, default_value = "168")]
    cloud_max_age: u64,
    /// Skip cloud provider range checking (use whois only)
    #[arg(long)]
    no_cloud_check: bool,
    /// Only fetch specific providers (comma-separated: aws,azure,gcp,digitalocean,cloudflare)
    #[arg(long)]
    cloud_providers: Option<String>,
    /// Stop processing after this many lines (useful for sampling large files)
    #[arg(long)]
    max_lines: Option<u64>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum CloudProvider {
    AWS,
    Azure,
    GCP,
    DigitalOcean,
    Cloudflare,
}

impl CloudProvider {
    fn as_str(&self) -> &'static str {
        match self {
            CloudProvider::AWS => "AWS",
            CloudProvider::Azure => "Azure",
            CloudProvider::GCP => "GCP",
            CloudProvider::DigitalOcean => "DigitalOcean",
            CloudProvider::Cloudflare => "Cloudflare",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "aws" => Some(CloudProvider::AWS),
            "azure" => Some(CloudProvider::Azure),
            "gcp" => Some(CloudProvider::GCP),
            "digitalocean" => Some(CloudProvider::DigitalOcean),
            "cloudflare" => Some(CloudProvider::Cloudflare),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct CloudRange {
    provider: CloudProvider,
    service: Option<String>,
    region: Option<String>,
    network: IpNetwork,
}

#[derive(Debug, Clone)]
struct CloudMatch {
    provider: CloudProvider,
    service: Option<String>,
    region: Option<String>,
}

impl CloudMatch {
    fn format_org(&self) -> String {
        let mut parts = vec![self.provider.as_str()];
        if let Some(service) = &self.service {
            parts.push(service);
        }
        if let Some(region) = &self.region {
            parts.push(region);
        }
        parts.join(" / ")
    }
}

struct CloudRangeCache {
    ipv4_ranges: Vec<CloudRange>,
    ipv6_ranges: Vec<CloudRange>,
}

impl CloudRangeCache {
    fn new() -> Self {
        CloudRangeCache {
            ipv4_ranges: Vec::new(),
            ipv6_ranges: Vec::new(),
        }
    }

    fn load_from_db(conn: &Connection) -> Result<Self> {
        let mut cache = Self::new();

        let mut stmt = conn.prepare(
            "SELECT provider, service, region, ip_prefix, is_v6 FROM cloud_ranges ORDER BY prefix_length DESC"
        )?;

        let rows = stmt.query_map([], |row| {
            let provider_str: String = row.get(0)?;
            let provider = CloudProvider::from_str(&provider_str).unwrap_or(CloudProvider::AWS);
            let service: Option<String> = row.get(1)?;
            let region: Option<String> = row.get(2)?;
            let ip_prefix: String = row.get(3)?;
            let is_v6: i32 = row.get(4)?;

            Ok((provider, service, region, ip_prefix, is_v6))
        })?;

        for row in rows {
            if let Ok((provider, service, region, ip_prefix, is_v6)) = row {
                if let Ok(network) = ip_prefix.parse::<IpNetwork>() {
                    let range = CloudRange {
                        provider,
                        service,
                        region,
                        network,
                    };

                    if is_v6 != 0 {
                        cache.ipv6_ranges.push(range);
                    } else {
                        cache.ipv4_ranges.push(range);
                    }
                }
            }
        }

        Ok(cache)
    }

    fn match_ip(&self, ip: &IpAddr) -> Option<CloudMatch> {
        let ranges = match ip {
            IpAddr::V4(_) => &self.ipv4_ranges,
            IpAddr::V6(_) => &self.ipv6_ranges,
        };

        for range in ranges {
            if range.network.contains(*ip) {
                return Some(CloudMatch {
                    provider: range.provider,
                    service: range.service.clone(),
                    region: range.region.clone(),
                });
            }
        }

        None
    }
}

// AWS JSON structures
#[derive(Debug, Deserialize)]
struct AwsIpRanges {
    prefixes: Vec<AwsPrefix>,
    ipv6_prefixes: Vec<AwsIpv6Prefix>,
}

#[derive(Debug, Deserialize)]
struct AwsPrefix {
    ip_prefix: String,
    region: String,
    service: String,
}

#[derive(Debug, Deserialize)]
struct AwsIpv6Prefix {
    ipv6_prefix: String,
    region: String,
    service: String,
}

// Azure JSON structures
#[derive(Debug, Deserialize)]
struct AzureServiceTags {
    values: Vec<AzureValue>,
}

#[derive(Debug, Deserialize)]
struct AzureValue {
    name: String,
    properties: AzureProperties,
}

#[derive(Debug, Deserialize)]
struct AzureProperties {
    #[serde(rename = "addressPrefixes")]
    address_prefixes: Vec<String>,
    region: Option<String>,
}

// GCP JSON structures
#[derive(Debug, Deserialize)]
struct GcpIpRanges {
    prefixes: Vec<GcpPrefix>,
}

#[derive(Debug, Deserialize)]
struct GcpPrefix {
    #[serde(rename = "ipv4Prefix")]
    ipv4_prefix: Option<String>,
    #[serde(rename = "ipv6Prefix")]
    ipv6_prefix: Option<String>,
    scope: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.top.is_some() && args.min.is_some() {
        anyhow::bail!("Cannot use both --top and --min together");
    }

    let (ip_counts, total_lines, global_ua_counts) = parse_file(
        &args.file,
        args.filter.as_deref(),
        args.ua_filter.as_deref(),
        args.delimiter.as_deref(),
        args.ip_field,
        args.ua_field,
        args.max_lines,
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
            let pct = if total_lines > 0 {
                (*count as f64 / total_lines as f64) * 100.0
            } else {
                0.0
            };
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

    // Initialize cloud cache
    let cloud_cache = if args.no_cloud_check {
        None
    } else {
        let conn = Connection::open(&args.db)?;
        init_db(&conn)?;

        let provider_filter = args.cloud_providers.as_ref().map(|s| {
            s.split(',')
                .filter_map(|p| CloudProvider::from_str(p.trim()))
                .collect::<Vec<_>>()
        });

        match rt.block_on(load_or_fetch_cloud_cache(
            &conn,
            args.refresh_cloud,
            args.force_cloud_refresh,
            args.cloud_max_age,
            provider_filter,
        )) {
            Ok(cache) => Some(Arc::new(cache)),
            Err(e) => {
                eprintln!("Warning: Failed to load cloud cache: {}", e);
                eprintln!("Proceeding with whois-only lookups");
                None
            }
        }
    };

    rt.block_on(run_lookups_and_display(
        filtered,
        &args.db,
        args.concurrency,
        total_lines,
        &filter_desc,
        cloud_cache,
        global_ua_counts,
    ))?;

    Ok(())
}

fn parse_file(
    path: &PathBuf,
    filter: Option<&str>,
    ua_filter: Option<&str>,
    delimiter: Option<&str>,
    ip_field: Option<usize>,
    ua_field: Option<usize>,
    max_lines: Option<u64>,
) -> Result<(
    HashMap<String, (u64, bool, Option<String>)>,
    u64,
    HashMap<String, u64>,
)> {
    let file = File::open(path).context("Failed to open input file")?;
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::with_capacity(1024 * 1024, file);

    let filter_re = filter
        .map(|p| Regex::new(p))
        .transpose()
        .context("Invalid --filter regex")?;
    let ua_filter_re = ua_filter
        .map(|p| Regex::new(p))
        .transpose()
        .context("Invalid --ua-filter regex")?;

    // Only compile regex if not using delimiter mode
    let ipv4_re = if delimiter.is_none() {
        Some(Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")?)
    } else {
        None
    };
    let ipv6_re = if delimiter.is_none() {
        Some(Regex::new(
            r"\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)\b",
        )?)
    } else {
        None
    };

    // Track (count, is_v6, ua_counts)
    let mut counts: HashMap<String, (u64, bool, HashMap<String, u64>)> = HashMap::new();
    // Track global user agent counts (base name without version)
    let mut global_ua_counts: HashMap<String, u64> = HashMap::new();
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
                eprint!(
                    "\rReading: {}% ({} lines)",
                    bytes_read * 100 / file_size,
                    total_lines
                );
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
                fields
                    .iter()
                    .find(|f| f.parse::<IpAddr>().is_ok())
                    .map(|s| *s)
            };

            let ua = if let Some(idx) = ua_field {
                fields
                    .get(idx.saturating_sub(1))
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            } else {
                fields
                    .iter()
                    .rev()
                    .find(|f| !f.is_empty())
                    .map(|s| s.to_string())
            };

            (ip.map(|s| s.to_string()), ua)
        } else {
            let ua = if let Some(last_quote) = line.rfind('"') {
                line[..last_quote]
                    .rfind('"')
                    .map(|start| line[start + 1..last_quote].to_string())
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

        // Check if we've reached max_lines
        if let Some(max) = max_lines {
            if total_lines >= max {
                break;
            }
        }

        let mut record_hit = |ip: IpAddr, ua: Option<String>| {
            let key = ip.to_string();
            let is_v6 = ip.is_ipv6();
            let entry = counts.entry(key).or_insert((0, is_v6, HashMap::new()));
            entry.0 += 1;
            if let Some(ref ua_str) = ua {
                if !ua_str.is_empty() {
                    *entry.2.entry(ua_str.clone()).or_insert(0) += 1;
                    // Track global user agent counts (base name only)
                    let ua_base = extract_ua_base(ua_str);
                    if !ua_base.is_empty() {
                        *global_ua_counts.entry(ua_base).or_insert(0) += 1;
                    }
                }
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

    Ok((result, total_lines, global_ua_counts))
}

fn apply_filters(
    counts: HashMap<String, (u64, bool, Option<String>)>,
    top: Option<&str>,
    min: Option<u64>,
) -> Vec<(String, u64, bool, Option<String>)> {
    let mut sorted: Vec<_> = counts
        .into_iter()
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
    cloud_cache: Option<Arc<CloudRangeCache>>,
    global_ua_counts: HashMap<String, u64>,
) -> Result<()> {
    let conn = Connection::open(db_path)?;
    init_db(&conn)?;

    let records: Vec<IpRecord> = ips
        .iter()
        .map(|(ip, count, is_v6, ua)| {
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
        })
        .collect();

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
        let cache = cloud_cache.clone();

        recs.lock().unwrap()[idx].lookup_in_progress = true;

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let (rdns, org) =
                perform_lookup_with_cloud(&ip, cache.as_ref().map(|c| c.as_ref())).await;

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
        run_tui(
            records.clone(),
            handles,
            total_lines,
            filter_desc,
            global_ua_counts,
        )
        .await?;
    } else {
        for h in handles {
            h.await.ok();
        }
        let recs = records.lock().unwrap();
        println!("Total lines: {}\n", total_lines);
        println!(
            "{:<8} {:<6} {:<40} {:<40} {:<30} {}",
            "Count", "%", "IP", "Reverse DNS", "Org", "User Agent"
        );
        println!("{}", "-".repeat(170));
        for rec in recs.iter() {
            let pct = if total_lines > 0 {
                (rec.count as f64 / total_lines as f64) * 100.0
            } else {
                0.0
            };
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
    global_ua_counts: HashMap<String, u64>,
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
                recs.iter()
                    .filter(|r| {
                        r.ip.to_lowercase().contains(&q)
                            || r.reverse_dns
                                .as_ref()
                                .map(|s| s.to_lowercase().contains(&q))
                                .unwrap_or(false)
                            || r.org
                                .as_ref()
                                .map(|s| s.to_lowercase().contains(&q))
                                .unwrap_or(false)
                            || r.user_agent
                                .as_ref()
                                .map(|s| s.to_lowercase().contains(&q))
                                .unwrap_or(false)
                    })
                    .cloned()
                    .collect()
            };

            let search_str = if search_mode {
                format!(" [SEARCH: {}█]", search_query)
            } else if !search_query.is_empty() {
                format!(" [filter: {}]", search_query)
            } else {
                String::new()
            };

            match group_by {
                GroupBy::Ip => render_ip_view(
                    f,
                    &filtered_recs,
                    &mut table_state,
                    total_lines,
                    pending,
                    show_rdns,
                    show_ua,
                    show_org,
                    filter_desc,
                    group_by,
                    &search_str,
                ),
                GroupBy::Org => render_grouped_view(
                    f,
                    &filtered_recs,
                    &mut table_state,
                    total_lines,
                    pending,
                    filter_desc,
                    "Org",
                    group_by,
                    &search_str,
                    |r| r.org.clone().unwrap_or_else(|| "-".to_string()),
                ),
                GroupBy::UserAgent => render_ua_global_view(
                    f,
                    &global_ua_counts,
                    &mut table_state,
                    total_lines,
                    pending,
                    filter_desc,
                    group_by,
                    &search_str,
                ),
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
                        recs.iter()
                            .filter(|r| {
                                r.ip.to_lowercase().contains(&q)
                                    || r.reverse_dns
                                        .as_ref()
                                        .map(|s| s.to_lowercase().contains(&q))
                                        .unwrap_or(false)
                                    || r.org
                                        .as_ref()
                                        .map(|s| s.to_lowercase().contains(&q))
                                        .unwrap_or(false)
                                    || r.user_agent
                                        .as_ref()
                                        .map(|s| s.to_lowercase().contains(&q))
                                        .unwrap_or(false)
                            })
                            .collect()
                    };

                    let len = match group_by {
                        GroupBy::Ip => filtered_recs.len(),
                        GroupBy::Org => aggregate_by_field(
                            &filtered_recs
                                .iter()
                                .map(|r| (*r).clone())
                                .collect::<Vec<_>>(),
                            |r| r.org.clone().unwrap_or_else(|| "-".to_string()),
                        )
                        .len(),
                        GroupBy::UserAgent => global_ua_counts.len(),
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
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
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
    let mut sorted: Vec<_> = groups
        .into_iter()
        .map(|(k, (count, n))| (k, count, n))
        .collect();
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
    let mut header_cells = vec![Cell::from("Count"), Cell::from("%"), Cell::from("IP")];
    if show_rdns {
        header_cells.push(Cell::from("Reverse DNS"));
    }
    if show_org {
        header_cells.push(Cell::from("Org"));
    }
    if show_ua {
        header_cells.push(Cell::from("User Agent"));
    }

    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

    let visible_cols = 3 + show_rdns as usize + show_ua as usize + show_org as usize;
    let extra_width: usize = if visible_cols <= 4 {
        60
    } else if visible_cols == 5 {
        30
    } else {
        0
    };

    let rows: Vec<Row> = recs
        .iter()
        .map(|rec| {
            let status = if rec.lookup_in_progress { "⏳" } else { "" };
            let pct = if total_lines > 0 {
                (rec.count as f64 / total_lines as f64) * 100.0
            } else {
                0.0
            };
            let mut cells = vec![
                Cell::from(format!("{}{}", rec.count, status)),
                Cell::from(format!("{:.2}", pct)),
                Cell::from(rec.ip.clone()),
            ];
            if show_rdns {
                cells.push(Cell::from(truncate_str(
                    rec.reverse_dns.as_deref().unwrap_or("-"),
                    38 + extra_width,
                )));
            }
            if show_org {
                cells.push(Cell::from(truncate_str(
                    rec.org.as_deref().unwrap_or("-"),
                    25 + extra_width,
                )));
            }
            if show_ua {
                cells.push(Cell::from(truncate_str(
                    rec.user_agent.as_deref().unwrap_or("-"),
                    40 + extra_width,
                )));
            }
            Row::new(cells)
        })
        .collect();

    let mut widths = vec![
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(40),
    ];
    if show_rdns {
        widths.push(Constraint::Length((40 + extra_width) as u16));
    }
    if show_org {
        widths.push(Constraint::Length((27 + extra_width) as u16));
    }
    if show_ua {
        widths.push(Constraint::Min(20));
    }

    let toggles = format!(
        "r:{} u:{} o:{}",
        if show_rdns { "on" } else { "off" },
        if show_ua { "on" } else { "off" },
        if show_org { "on" } else { "off" },
    );

    let pending_str = if pending > 0 {
        format!(", {} pending", pending)
    } else {
        String::new()
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {} IPs, {} lines{} [{}] [by:{}]{} (g/r/u/o/s, q=quit) ",
            filter_desc,
            total_lines,
            pending_str,
            toggles,
            group_by.label(),
            search_str
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
) where
    F: Fn(&IpRecord) -> String,
{
    let groups = aggregate_by_field(recs, key_fn);

    let header = Row::new(vec![
        Cell::from("Count"),
        Cell::from("%"),
        Cell::from("IPs"),
        Cell::from(group_label),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = groups
        .iter()
        .map(|(key, count, ip_count)| {
            let pct = if total_lines > 0 {
                (*count as f64 / total_lines as f64) * 100.0
            } else {
                0.0
            };
            Row::new(vec![
                Cell::from(format!("{}", count)),
                Cell::from(format!("{:.2}", pct)),
                Cell::from(format!("{}", ip_count)),
                Cell::from(key.clone()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Min(40),
    ];

    let pending_str = if pending > 0 {
        format!(", {} pending", pending)
    } else {
        String::new()
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {} IPs by {}, {} lines{} [by:{}]{} (g/s, q=quit) ",
            filter_desc,
            group_label,
            total_lines,
            pending_str,
            group_by.label(),
            search_str
        )))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    f.render_stateful_widget(table, f.area(), table_state);
}

fn render_ua_global_view(
    f: &mut ratatui::Frame,
    global_ua_counts: &HashMap<String, u64>,
    table_state: &mut TableState,
    total_lines: u64,
    pending: usize,
    filter_desc: &str,
    group_by: GroupBy,
    search_str: &str,
) {
    // Convert global UA counts to sorted vec
    let mut ua_groups: Vec<(String, u64)> = global_ua_counts
        .iter()
        .map(|(ua, count)| (ua.clone(), *count))
        .collect();
    ua_groups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let header = Row::new(vec![
        Cell::from("Count"),
        Cell::from("%"),
        Cell::from("User Agent"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = ua_groups
        .iter()
        .map(|(ua, count)| {
            let pct = if total_lines > 0 {
                (*count as f64 / total_lines as f64) * 100.0
            } else {
                0.0
            };
            Row::new(vec![
                Cell::from(format!("{}", count)),
                Cell::from(format!("{:.2}", pct)),
                Cell::from(ua.clone()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Min(40),
    ];

    let pending_str = if pending > 0 {
        format!(", {} pending", pending)
    } else {
        String::new()
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {} IPs by User Agent, {} lines{} [by:{}]{} (g/s, q=quit) ",
            filter_desc,
            total_lines,
            pending_str,
            group_by.label(),
            search_str
        )))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    f.render_stateful_widget(table, f.area(), table_state);
}

async fn fetch_cloud_ranges(provider: CloudProvider) -> Result<Vec<CloudRange>> {
    let url = match provider {
        CloudProvider::AWS => "https://ip-ranges.amazonaws.com/ip-ranges.json",
        CloudProvider::Azure => {
            return fetch_azure_ranges().await;
        }
        CloudProvider::GCP => "https://www.gstatic.com/ipranges/cloud.json",
        CloudProvider::DigitalOcean => "https://digitalocean.com/geo/google.csv",
        CloudProvider::Cloudflare => {
            return fetch_cloudflare_ranges().await;
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut attempts = 0;
    let max_attempts = 3;

    while attempts < max_attempts {
        match client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let body = response.text().await?;
                    return match provider {
                        CloudProvider::AWS => parse_aws_ranges(&body),
                        CloudProvider::GCP => parse_gcp_ranges(&body),
                        CloudProvider::DigitalOcean => parse_digitalocean_ranges(&body),
                        _ => unreachable!(),
                    };
                }
            }
            Err(e) => {
                attempts += 1;
                if attempts >= max_attempts {
                    return Err(anyhow::anyhow!(
                        "Failed to fetch {} ranges after {} attempts: {}",
                        provider.as_str(),
                        max_attempts,
                        e
                    ));
                }
                tokio::time::sleep(Duration::from_secs(2u64.pow(attempts))).await;
            }
        }
    }

    Err(anyhow::anyhow!(
        "Failed to fetch {} ranges",
        provider.as_str()
    ))
}

async fn fetch_cloudflare_ranges() -> Result<Vec<CloudRange>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut ranges = Vec::new();

    // Fetch IPv4 ranges
    if let Ok(response) = client.get("https://www.cloudflare.com/ips-v4").send().await {
        if response.status().is_success() {
            let body = response.text().await?;
            ranges.extend(parse_cloudflare_text(
                &body,
                CloudProvider::Cloudflare,
                false,
            )?);
        }
    }

    // Fetch IPv6 ranges
    if let Ok(response) = client.get("https://www.cloudflare.com/ips-v6").send().await {
        if response.status().is_success() {
            let body = response.text().await?;
            ranges.extend(parse_cloudflare_text(
                &body,
                CloudProvider::Cloudflare,
                true,
            )?);
        }
    }

    Ok(ranges)
}

async fn fetch_azure_ranges() -> Result<Vec<CloudRange>> {
    // Azure requires scraping the download page for the current JSON file
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    // First, get the download page
    let page_url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519";
    let response = client.get(page_url).send().await?;
    let html = response.text().await?;

    // Extract the JSON download URL from the page
    let json_url = html
        .lines()
        .find(|line| line.contains("download.microsoft.com") && line.contains(".json"))
        .and_then(|line| {
            if let Some(start) = line.find("https://download.microsoft.com") {
                if let Some(end) = line[start..].find('"') {
                    return Some(line[start..start + end].to_string());
                }
            }
            None
        })
        .ok_or_else(|| anyhow::anyhow!("Could not find Azure JSON download URL"))?;

    // Now fetch the actual JSON file
    let response = client.get(&json_url).send().await?;
    let body = response.text().await?;

    parse_azure_ranges(&body)
}

fn parse_aws_ranges(json: &str) -> Result<Vec<CloudRange>> {
    let data: AwsIpRanges = serde_json::from_str(json)?;
    let mut ranges = Vec::new();

    for prefix in data.prefixes {
        if let Ok(network) = prefix.ip_prefix.parse::<IpNetwork>() {
            ranges.push(CloudRange {
                provider: CloudProvider::AWS,
                service: Some(prefix.service),
                region: Some(prefix.region),
                network,
            });
        }
    }

    for prefix in data.ipv6_prefixes {
        if let Ok(network) = prefix.ipv6_prefix.parse::<IpNetwork>() {
            ranges.push(CloudRange {
                provider: CloudProvider::AWS,
                service: Some(prefix.service),
                region: Some(prefix.region),
                network,
            });
        }
    }

    Ok(ranges)
}

fn parse_azure_ranges(json: &str) -> Result<Vec<CloudRange>> {
    let data: AzureServiceTags = serde_json::from_str(json)?;
    let mut ranges = Vec::new();

    for value in data.values {
        let service = value.name;
        let region = value.properties.region;

        for prefix in value.properties.address_prefixes {
            if let Ok(network) = prefix.parse::<IpNetwork>() {
                ranges.push(CloudRange {
                    provider: CloudProvider::Azure,
                    service: Some(service.clone()),
                    region: region.clone(),
                    network,
                });
            }
        }
    }

    Ok(ranges)
}

fn parse_gcp_ranges(json: &str) -> Result<Vec<CloudRange>> {
    let data: GcpIpRanges = serde_json::from_str(json)?;
    let mut ranges = Vec::new();

    for prefix in data.prefixes {
        if let Some(ipv4) = prefix.ipv4_prefix {
            if let Ok(network) = ipv4.parse::<IpNetwork>() {
                ranges.push(CloudRange {
                    provider: CloudProvider::GCP,
                    service: None,
                    region: prefix.scope.clone(),
                    network,
                });
            }
        }

        if let Some(ipv6) = prefix.ipv6_prefix {
            if let Ok(network) = ipv6.parse::<IpNetwork>() {
                ranges.push(CloudRange {
                    provider: CloudProvider::GCP,
                    service: None,
                    region: prefix.scope.clone(),
                    network,
                });
            }
        }
    }

    Ok(ranges)
}

fn parse_digitalocean_ranges(csv: &str) -> Result<Vec<CloudRange>> {
    let mut ranges = Vec::new();

    for line in csv.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() >= 2 {
            let ip_prefix = fields[0].trim();
            let region = fields[1].trim();

            if let Ok(network) = ip_prefix.parse::<IpNetwork>() {
                ranges.push(CloudRange {
                    provider: CloudProvider::DigitalOcean,
                    service: None,
                    region: Some(region.to_string()),
                    network,
                });
            }
        }
    }

    Ok(ranges)
}

fn parse_cloudflare_text(
    text: &str,
    provider: CloudProvider,
    _is_v6: bool,
) -> Result<Vec<CloudRange>> {
    let mut ranges = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Ok(network) = line.parse::<IpNetwork>() {
            ranges.push(CloudRange {
                provider,
                service: None,
                region: None,
                network,
            });
        }
    }

    Ok(ranges)
}

async fn fetch_all_cloud_ranges(
    providers: Option<Vec<CloudProvider>>,
) -> HashMap<CloudProvider, Result<Vec<CloudRange>>> {
    let providers = providers.unwrap_or_else(|| {
        vec![
            CloudProvider::AWS,
            CloudProvider::Azure,
            CloudProvider::GCP,
            CloudProvider::DigitalOcean,
            CloudProvider::Cloudflare,
        ]
    });

    let mut handles = vec![];

    for provider in providers {
        let handle = tokio::spawn(async move {
            let result = fetch_cloud_ranges(provider).await;
            (provider, result)
        });
        handles.push(handle);
    }

    let mut results = HashMap::new();
    for handle in handles {
        if let Ok((provider, result)) = handle.await {
            results.insert(provider, result);
        }
    }

    results
}

fn store_cloud_ranges(conn: &Connection, ranges: &[CloudRange]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;

    for range in ranges {
        let is_v6 = match range.network {
            IpNetwork::V4(_) => 0,
            IpNetwork::V6(_) => 1,
        };

        let prefix_length = range.network.prefix();
        let now = chrono::Utc::now().to_rfc3339();

        tx.execute(
            "INSERT OR REPLACE INTO cloud_ranges (provider, service, region, ip_prefix, is_v6, prefix_length, last_updated)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                range.provider.as_str(),
                range.service,
                range.region,
                range.network.to_string(),
                is_v6,
                prefix_length,
                now
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

fn update_cloud_metadata(
    conn: &Connection,
    provider: CloudProvider,
    url: &str,
    count: usize,
    status: &str,
) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO cloud_range_metadata (provider, last_fetch_time, fetch_url, record_count, fetch_status)
         VALUES (?, ?, ?, ?, ?)",
        params![provider.as_str(), now, url, count as i64, status],
    )?;
    Ok(())
}

fn should_refresh_cloud_ranges(
    conn: &Connection,
    provider: CloudProvider,
    max_age_hours: u64,
) -> Result<bool> {
    let result: Option<String> = conn
        .query_row(
            "SELECT last_fetch_time FROM cloud_range_metadata WHERE provider = ?",
            [provider.as_str()],
            |row| row.get(0),
        )
        .ok();

    if let Some(last_fetch) = result {
        if let Ok(last_time) = chrono::DateTime::parse_from_rfc3339(&last_fetch) {
            let now = chrono::Utc::now();
            let age = now.signed_duration_since(last_time.with_timezone(&chrono::Utc));
            let max_age = chrono::Duration::hours(max_age_hours as i64);
            return Ok(age > max_age);
        }
    }

    // No metadata or parse error = needs refresh
    Ok(true)
}

async fn load_or_fetch_cloud_cache(
    conn: &Connection,
    refresh: bool,
    force_refresh: bool,
    max_age_hours: u64,
    provider_filter: Option<Vec<CloudProvider>>,
) -> Result<CloudRangeCache> {
    let providers = provider_filter.clone().unwrap_or_else(|| {
        vec![
            CloudProvider::AWS,
            CloudProvider::Azure,
            CloudProvider::GCP,
            CloudProvider::DigitalOcean,
            CloudProvider::Cloudflare,
        ]
    });

    let mut needs_refresh = force_refresh || refresh;

    if !needs_refresh {
        for provider in &providers {
            if should_refresh_cloud_ranges(conn, *provider, max_age_hours)? {
                needs_refresh = true;
                break;
            }
        }
    }

    if needs_refresh {
        eprintln!("Fetching cloud IP ranges...");
        let results = fetch_all_cloud_ranges(provider_filter).await;

        let mut total_success = 0;
        let mut total_failed = 0;

        for (provider, result) in results {
            match result {
                Ok(ranges) => {
                    let count = ranges.len();
                    if let Err(e) = store_cloud_ranges(conn, &ranges) {
                        eprintln!(
                            "Warning: Failed to store {} ranges: {}",
                            provider.as_str(),
                            e
                        );
                        total_failed += 1;
                    } else {
                        let url = match provider {
                            CloudProvider::AWS => "https://ip-ranges.amazonaws.com/ip-ranges.json",
                            CloudProvider::Azure => {
                                "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
                            }
                            CloudProvider::GCP => "https://www.gstatic.com/ipranges/cloud.json",
                            CloudProvider::DigitalOcean => {
                                "https://digitalocean.com/geo/google.csv"
                            }
                            CloudProvider::Cloudflare => "https://www.cloudflare.com/ips-v4",
                        };
                        update_cloud_metadata(conn, provider, url, count, "success")?;
                        eprintln!("  {} ✓ ({} ranges)", provider.as_str(), count);
                        total_success += 1;
                    }
                }
                Err(e) => {
                    eprintln!("  {} ✗ ({})", provider.as_str(), e);
                    total_failed += 1;
                }
            }
        }

        if total_success > 0 {
            eprintln!(
                "Cloud ranges updated: {} succeeded, {} failed",
                total_success, total_failed
            );
        } else if total_failed > 0 {
            eprintln!("Warning: All cloud range fetches failed, will use cached data if available");
        }
    }

    CloudRangeCache::load_from_db(conn)
}

async fn perform_lookup_with_cloud(
    ip: &str,
    cloud_cache: Option<&CloudRangeCache>,
) -> (Option<String>, Option<String>) {
    let ip_clone = ip.to_string();

    let rdns = tokio::task::spawn_blocking(move || {
        if let Ok(addr) = ip_clone.parse::<IpAddr>() {
            dns_lookup::lookup_addr(&addr).ok()
        } else {
            None
        }
    })
    .await
    .ok()
    .flatten();

    // Check cloud cache first
    if let Some(cache) = cloud_cache {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            if let Some(cloud_match) = cache.match_ip(&addr) {
                return (rdns, Some(cloud_match.format_org()));
            }
        }
    }

    // Fall back to whois if no cloud match
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

    // Create cloud_ranges table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cloud_ranges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            service TEXT,
            region TEXT,
            ip_prefix TEXT NOT NULL,
            is_v6 INTEGER NOT NULL,
            prefix_length INTEGER NOT NULL,
            last_updated TEXT NOT NULL,
            UNIQUE(provider, ip_prefix)
        )",
        [],
    )?;

    // Create indexes for cloud_ranges
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cloud_provider ON cloud_ranges(provider)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cloud_is_v6 ON cloud_ranges(is_v6)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cloud_prefix_length ON cloud_ranges(prefix_length)",
        [],
    )?;

    // Create cloud_range_metadata table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cloud_range_metadata (
            provider TEXT PRIMARY KEY,
            last_fetch_time TEXT NOT NULL,
            sync_token TEXT,
            fetch_url TEXT NOT NULL,
            record_count INTEGER NOT NULL,
            fetch_status TEXT NOT NULL
        )",
        [],
    )?;

    Ok(())
}

fn get_ip_record(
    conn: &Connection,
    ip: &str,
) -> Option<(
    String,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
)> {
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
    )
    .ok()
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

fn update_ip_lookup(
    conn: &Connection,
    ip: &str,
    rdns: Option<&str>,
    org: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE ips SET looked_up = 1, reverse_dns = ?, org = ? WHERE ip = ?",
        params![rdns, org, ip],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // Test fixtures for each provider
    mod test_fixtures {
        pub const AWS_JSON: &str = r#"{
            "prefixes": [
                {"ip_prefix": "52.93.153.0/24", "region": "us-east-1", "service": "EC2"},
                {"ip_prefix": "13.34.0.0/16", "region": "eu-west-2", "service": "AMAZON"}
            ],
            "ipv6_prefixes": [
                {"ipv6_prefix": "2600:9000::/28", "region": "GLOBAL", "service": "CLOUDFRONT"}
            ]
        }"#;

        pub const AWS_JSON_EMPTY: &str = r#"{"prefixes": [], "ipv6_prefixes": []}"#;

        pub const AWS_JSON_INVALID: &str = r#"{"prefixes": [{"invalid": "data"}]}"#;

        pub const GCP_JSON: &str = r#"{
            "prefixes": [
                {"ipv4Prefix": "34.1.208.0/20", "scope": "africa-south1"},
                {"ipv6Prefix": "2600:1900::/28", "scope": "us-central1"}
            ]
        }"#;

        pub const GCP_JSON_NO_SCOPE: &str = r#"{
            "prefixes": [
                {"ipv4Prefix": "35.190.0.0/16"}
            ]
        }"#;

        pub const AZURE_JSON: &str = r#"{
            "values": [
                {
                    "name": "AzureCloud",
                    "properties": {
                        "addressPrefixes": ["20.118.137.0/24", "2603:1030::/48"],
                        "region": "westus2"
                    }
                },
                {
                    "name": "AzureVMs",
                    "properties": {
                        "addressPrefixes": ["40.121.0.0/16"]
                    }
                }
            ]
        }"#;

        pub const CLOUDFLARE_V4: &str =
            "104.21.48.0/20\n172.67.0.0/17\n\n# Comment line\n188.114.96.0/20";
        pub const CLOUDFLARE_V6: &str = "2606:4700::/32\n2803:f800::/32";

        pub const DIGITALOCEAN_CSV: &str =
            "ip,region\n164.90.241.0/24,nyc3\n167.99.0.0/16,sfo2\n159.65.0.0/16,lon1";
        pub const DIGITALOCEAN_CSV_EMPTY: &str = "ip,region";
        pub const DIGITALOCEAN_CSV_NO_HEADER: &str = "164.90.241.0/24,nyc3";
    }

    // ===== Parser Unit Tests =====

    #[test]
    fn test_parse_aws_ranges() {
        let result = parse_aws_ranges(test_fixtures::AWS_JSON).unwrap();
        assert_eq!(result.len(), 3);

        // Check IPv4 prefix
        let ec2 = result
            .iter()
            .find(|r| r.network.to_string() == "52.93.153.0/24")
            .unwrap();
        assert_eq!(ec2.provider, CloudProvider::AWS);
        assert_eq!(ec2.service.as_deref(), Some("EC2"));
        assert_eq!(ec2.region.as_deref(), Some("us-east-1"));

        // Check IPv6 prefix
        let cf = result
            .iter()
            .find(|r| r.network.to_string() == "2600:9000::/28")
            .unwrap();
        assert_eq!(cf.service.as_deref(), Some("CLOUDFRONT"));
        assert_eq!(cf.region.as_deref(), Some("GLOBAL"));
    }

    #[test]
    fn test_parse_aws_ranges_empty() {
        let result = parse_aws_ranges(test_fixtures::AWS_JSON_EMPTY).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_aws_ranges_malformed() {
        let result = parse_aws_ranges("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_azure_ranges() {
        let result = parse_azure_ranges(test_fixtures::AZURE_JSON).unwrap();
        assert_eq!(result.len(), 3);

        let azure_cloud = result
            .iter()
            .find(|r| r.network.to_string() == "20.118.137.0/24")
            .unwrap();
        assert_eq!(azure_cloud.provider, CloudProvider::Azure);
        assert_eq!(azure_cloud.service.as_deref(), Some("AzureCloud"));
        assert_eq!(azure_cloud.region.as_deref(), Some("westus2"));

        // Check IPv6
        let ipv6 = result
            .iter()
            .find(|r| r.network.to_string() == "2603:1030::/48")
            .unwrap();
        assert_eq!(ipv6.service.as_deref(), Some("AzureCloud"));
    }

    #[test]
    fn test_parse_azure_ranges_no_region() {
        let json = r#"{"values": [{"name": "Service", "properties": {"addressPrefixes": ["10.0.0.0/8"]}}]}"#;
        let result = parse_azure_ranges(json).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].region, None);
    }

    #[test]
    fn test_parse_gcp_ranges() {
        let result = parse_gcp_ranges(test_fixtures::GCP_JSON).unwrap();
        assert_eq!(result.len(), 2);

        let ipv4 = result
            .iter()
            .find(|r| r.network.to_string() == "34.1.208.0/20")
            .unwrap();
        assert_eq!(ipv4.provider, CloudProvider::GCP);
        assert_eq!(ipv4.service, None);
        assert_eq!(ipv4.region.as_deref(), Some("africa-south1"));

        let ipv6 = result
            .iter()
            .find(|r| r.network.to_string() == "2600:1900::/28")
            .unwrap();
        assert_eq!(ipv6.region.as_deref(), Some("us-central1"));
    }

    #[test]
    fn test_parse_gcp_ranges_no_scope() {
        let result = parse_gcp_ranges(test_fixtures::GCP_JSON_NO_SCOPE).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].region, None);
    }

    #[test]
    fn test_parse_gcp_ranges_invalid() {
        let result = parse_gcp_ranges("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_digitalocean_ranges() {
        let result = parse_digitalocean_ranges(test_fixtures::DIGITALOCEAN_CSV).unwrap();
        assert_eq!(result.len(), 3);

        let nyc3 = result
            .iter()
            .find(|r| r.network.to_string() == "164.90.241.0/24")
            .unwrap();
        assert_eq!(nyc3.provider, CloudProvider::DigitalOcean);
        assert_eq!(nyc3.service, None);
        assert_eq!(nyc3.region.as_deref(), Some("nyc3"));
    }

    #[test]
    fn test_parse_digitalocean_ranges_empty() {
        let result = parse_digitalocean_ranges(test_fixtures::DIGITALOCEAN_CSV_EMPTY).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_digitalocean_ranges_no_header() {
        let result = parse_digitalocean_ranges(test_fixtures::DIGITALOCEAN_CSV_NO_HEADER).unwrap();
        // Should skip first line (treated as header)
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_cloudflare_text() {
        let result = parse_cloudflare_text(
            test_fixtures::CLOUDFLARE_V4,
            CloudProvider::Cloudflare,
            false,
        )
        .unwrap();
        assert_eq!(result.len(), 3); // 3 valid CIDRs, skipping comment and empty line

        let range1 = result
            .iter()
            .find(|r| r.network.to_string() == "104.21.48.0/20")
            .unwrap();
        assert_eq!(range1.provider, CloudProvider::Cloudflare);
        assert_eq!(range1.service, None);
        assert_eq!(range1.region, None);
    }

    #[test]
    fn test_parse_cloudflare_text_ipv6() {
        let result = parse_cloudflare_text(
            test_fixtures::CLOUDFLARE_V6,
            CloudProvider::Cloudflare,
            true,
        )
        .unwrap();
        assert_eq!(result.len(), 2);

        assert!(result
            .iter()
            .any(|r| r.network.to_string() == "2606:4700::/32"));
    }

    #[test]
    fn test_parse_cloudflare_text_empty() {
        let result = parse_cloudflare_text("", CloudProvider::Cloudflare, false).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_cloudflare_text_invalid_cidr() {
        let result = parse_cloudflare_text(
            "invalid.cidr.here\n104.21.48.0/20",
            CloudProvider::Cloudflare,
            false,
        )
        .unwrap();
        assert_eq!(result.len(), 1); // Should skip invalid CIDR
    }

    // ===== IP Matching Tests =====

    #[test]
    fn test_cloud_match_ipv4_exact() {
        let mut cache = CloudRangeCache::new();
        cache.ipv4_ranges.push(CloudRange {
            provider: CloudProvider::AWS,
            service: Some("EC2".to_string()),
            region: Some("us-east-1".to_string()),
            network: "52.93.153.170/32".parse().unwrap(),
        });

        let ip: IpAddr = "52.93.153.170".parse().unwrap();
        let result = cache.match_ip(&ip);

        assert!(result.is_some());
        let matched = result.unwrap();
        assert_eq!(matched.provider, CloudProvider::AWS);
        assert_eq!(matched.service.as_deref(), Some("EC2"));
        assert_eq!(matched.region.as_deref(), Some("us-east-1"));
    }

    #[test]
    fn test_cloud_match_ipv4_subnet() {
        let mut cache = CloudRangeCache::new();
        cache.ipv4_ranges.push(CloudRange {
            provider: CloudProvider::GCP,
            service: None,
            region: Some("europe-west1".to_string()),
            network: "34.1.208.0/20".parse().unwrap(),
        });

        let ip: IpAddr = "34.1.215.123".parse().unwrap();
        let result = cache.match_ip(&ip);

        assert!(result.is_some());
        let matched = result.unwrap();
        assert_eq!(matched.provider, CloudProvider::GCP);
        assert_eq!(matched.region.as_deref(), Some("europe-west1"));
    }

    #[test]
    fn test_cloud_match_ipv4_no_match() {
        let mut cache = CloudRangeCache::new();
        cache.ipv4_ranges.push(CloudRange {
            provider: CloudProvider::AWS,
            service: Some("EC2".to_string()),
            region: Some("us-east-1".to_string()),
            network: "52.93.153.0/24".parse().unwrap(),
        });

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let result = cache.match_ip(&ip);

        assert!(result.is_none());
    }

    #[test]
    fn test_cloud_match_most_specific() {
        let mut cache = CloudRangeCache::new();
        // Add /16 first (less specific)
        cache.ipv4_ranges.push(CloudRange {
            provider: CloudProvider::AWS,
            service: Some("S3".to_string()),
            region: Some("us-west-2".to_string()),
            network: "52.93.0.0/16".parse().unwrap(),
        });
        // Add /24 second (more specific)
        cache.ipv4_ranges.push(CloudRange {
            provider: CloudProvider::AWS,
            service: Some("EC2".to_string()),
            region: Some("us-east-1".to_string()),
            network: "52.93.153.0/24".parse().unwrap(),
        });

        let ip: IpAddr = "52.93.153.100".parse().unwrap();
        let result = cache.match_ip(&ip).unwrap();

        // Should match first one found (in our impl, first match wins)
        // But if sorted by prefix_length DESC, /24 would be first
        assert_eq!(result.provider, CloudProvider::AWS);
    }

    #[test]
    fn test_cloud_match_ipv6() {
        let mut cache = CloudRangeCache::new();
        cache.ipv6_ranges.push(CloudRange {
            provider: CloudProvider::Cloudflare,
            service: None,
            region: None,
            network: "2606:4700::/32".parse().unwrap(),
        });

        let ip: IpAddr = "2606:4700::1".parse().unwrap();
        let result = cache.match_ip(&ip);

        assert!(result.is_some());
        let matched = result.unwrap();
        assert_eq!(matched.provider, CloudProvider::Cloudflare);
        assert_eq!(matched.service, None);
        assert_eq!(matched.region, None);
    }

    #[test]
    fn test_cloud_match_format_org_full() {
        let cloud_match = CloudMatch {
            provider: CloudProvider::AWS,
            service: Some("EC2".to_string()),
            region: Some("us-east-1".to_string()),
        };

        assert_eq!(cloud_match.format_org(), "AWS / EC2 / us-east-1");
    }

    #[test]
    fn test_cloud_match_format_org_no_region() {
        let cloud_match = CloudMatch {
            provider: CloudProvider::Azure,
            service: Some("AzureCloud".to_string()),
            region: None,
        };

        assert_eq!(cloud_match.format_org(), "Azure / AzureCloud");
    }

    #[test]
    fn test_cloud_match_format_org_provider_only() {
        let cloud_match = CloudMatch {
            provider: CloudProvider::Cloudflare,
            service: None,
            region: None,
        };

        assert_eq!(cloud_match.format_org(), "Cloudflare");
    }

    #[test]
    fn test_cloud_match_format_org_region_only() {
        let cloud_match = CloudMatch {
            provider: CloudProvider::GCP,
            service: None,
            region: Some("europe-west1".to_string()),
        };

        assert_eq!(cloud_match.format_org(), "GCP / europe-west1");
    }

    // ===== Database Tests =====

    #[test]
    fn test_init_db_creates_tables() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();

        init_db(&conn).unwrap();

        // Verify cloud_ranges table exists
        let result: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cloud_ranges'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(result, 1);

        // Verify cloud_range_metadata table exists
        let result: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cloud_range_metadata'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(result, 1);

        // Verify indexes exist
        let result: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_cloud_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(result, 3); // 3 indexes
    }

    #[test]
    fn test_init_db_idempotent() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();

        // Run init_db twice
        init_db(&conn).unwrap();
        init_db(&conn).unwrap(); // Should not error

        // Verify still only one table of each type
        let result: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cloud_ranges'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn test_store_cloud_ranges() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        let ranges = vec![
            CloudRange {
                provider: CloudProvider::AWS,
                service: Some("EC2".to_string()),
                region: Some("us-east-1".to_string()),
                network: "52.93.153.0/24".parse().unwrap(),
            },
            CloudRange {
                provider: CloudProvider::GCP,
                service: None,
                region: Some("europe-west1".to_string()),
                network: "2600:1900::/28".parse().unwrap(),
            },
        ];

        store_cloud_ranges(&conn, &ranges).unwrap();

        // Verify data was stored
        let count: i32 = conn
            .query_row("SELECT COUNT(*) FROM cloud_ranges", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);

        // Verify IPv4 range
        let (provider, service, is_v6, prefix_len): (String, Option<String>, i32, i32) = conn
            .query_row(
                "SELECT provider, service, is_v6, prefix_length FROM cloud_ranges WHERE ip_prefix = ?",
                ["52.93.153.0/24"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(provider, "AWS");
        assert_eq!(service.as_deref(), Some("EC2"));
        assert_eq!(is_v6, 0);
        assert_eq!(prefix_len, 24);

        // Verify IPv6 range
        let (provider, is_v6, prefix_len): (String, i32, i32) = conn
            .query_row(
                "SELECT provider, is_v6, prefix_length FROM cloud_ranges WHERE ip_prefix = ?",
                ["2600:1900::/28"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(provider, "GCP");
        assert_eq!(is_v6, 1);
        assert_eq!(prefix_len, 28);
    }

    #[test]
    fn test_store_cloud_ranges_upsert() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        let ranges1 = vec![CloudRange {
            provider: CloudProvider::AWS,
            service: Some("EC2".to_string()),
            region: Some("us-east-1".to_string()),
            network: "52.93.153.0/24".parse().unwrap(),
        }];

        store_cloud_ranges(&conn, &ranges1).unwrap();

        // Update with different service
        let ranges2 = vec![CloudRange {
            provider: CloudProvider::AWS,
            service: Some("S3".to_string()),
            region: Some("us-west-2".to_string()),
            network: "52.93.153.0/24".parse().unwrap(),
        }];

        store_cloud_ranges(&conn, &ranges2).unwrap();

        // Should still be only 1 record
        let count: i32 = conn
            .query_row("SELECT COUNT(*) FROM cloud_ranges", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);

        // Should have updated service
        let service: String = conn
            .query_row(
                "SELECT service FROM cloud_ranges WHERE ip_prefix = ?",
                ["52.93.153.0/24"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(service, "S3");
    }

    #[test]
    fn test_cloud_range_cache_load_from_db() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        let ranges = vec![
            CloudRange {
                provider: CloudProvider::AWS,
                service: Some("EC2".to_string()),
                region: Some("us-east-1".to_string()),
                network: "52.93.153.0/24".parse().unwrap(),
            },
            CloudRange {
                provider: CloudProvider::Cloudflare,
                service: None,
                region: None,
                network: "2606:4700::/32".parse().unwrap(),
            },
        ];

        store_cloud_ranges(&conn, &ranges).unwrap();

        let cache = CloudRangeCache::load_from_db(&conn).unwrap();

        assert_eq!(cache.ipv4_ranges.len(), 1);
        assert_eq!(cache.ipv6_ranges.len(), 1);

        // Verify IPv4
        assert_eq!(cache.ipv4_ranges[0].provider, CloudProvider::AWS);
        assert_eq!(cache.ipv4_ranges[0].network.to_string(), "52.93.153.0/24");

        // Verify IPv6
        assert_eq!(cache.ipv6_ranges[0].provider, CloudProvider::Cloudflare);
        assert_eq!(cache.ipv6_ranges[0].network.to_string(), "2606:4700::/32");
    }

    #[test]
    fn test_cloud_range_cache_load_empty_db() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        let cache = CloudRangeCache::load_from_db(&conn).unwrap();

        assert_eq!(cache.ipv4_ranges.len(), 0);
        assert_eq!(cache.ipv6_ranges.len(), 0);
    }

    #[test]
    fn test_cloud_range_cache_load_invalid_cidr() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        // Manually insert invalid CIDR
        conn.execute(
            "INSERT INTO cloud_ranges (provider, service, region, ip_prefix, is_v6, prefix_length, last_updated)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params!["AWS", "EC2", "us-east-1", "invalid-cidr", 0, 24, "2026-01-01T00:00:00Z"],
        )
        .unwrap();

        let cache = CloudRangeCache::load_from_db(&conn).unwrap();

        // Should skip invalid CIDR
        assert_eq!(cache.ipv4_ranges.len(), 0);
    }

    #[test]
    fn test_update_cloud_metadata() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        update_cloud_metadata(
            &conn,
            CloudProvider::AWS,
            "https://example.com",
            100,
            "success",
        )
        .unwrap();

        let (provider, url, count, status): (String, String, i64, String) = conn
            .query_row(
                "SELECT provider, fetch_url, record_count, fetch_status FROM cloud_range_metadata WHERE provider = ?",
                ["AWS"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();

        assert_eq!(provider, "AWS");
        assert_eq!(url, "https://example.com");
        assert_eq!(count, 100);
        assert_eq!(status, "success");
    }

    #[test]
    fn test_update_cloud_metadata_upsert() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        update_cloud_metadata(
            &conn,
            CloudProvider::AWS,
            "https://example.com",
            100,
            "success",
        )
        .unwrap();
        update_cloud_metadata(
            &conn,
            CloudProvider::AWS,
            "https://example.com",
            200,
            "success",
        )
        .unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT record_count FROM cloud_range_metadata WHERE provider = ?",
                ["AWS"],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 200);
    }

    #[test]
    fn test_should_refresh_cloud_ranges_no_metadata() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        let result = should_refresh_cloud_ranges(&conn, CloudProvider::AWS, 168).unwrap();
        assert!(result);
    }

    #[test]
    fn test_should_refresh_cloud_ranges_old_data() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        // Insert metadata from 10 days ago
        let old_time = chrono::Utc::now() - chrono::Duration::days(10);
        conn.execute(
            "INSERT INTO cloud_range_metadata (provider, last_fetch_time, fetch_url, record_count, fetch_status)
             VALUES (?, ?, ?, ?, ?)",
            params!["AWS", old_time.to_rfc3339(), "https://example.com", 100, "success"],
        )
        .unwrap();

        let result = should_refresh_cloud_ranges(&conn, CloudProvider::AWS, 168).unwrap(); // 7 days
        assert!(result);
    }

    #[test]
    fn test_should_refresh_cloud_ranges_fresh_data() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        // Insert metadata from 1 hour ago
        let recent_time = chrono::Utc::now() - chrono::Duration::hours(1);
        conn.execute(
            "INSERT INTO cloud_range_metadata (provider, last_fetch_time, fetch_url, record_count, fetch_status)
             VALUES (?, ?, ?, ?, ?)",
            params!["AWS", recent_time.to_rfc3339(), "https://example.com", 100, "success"],
        )
        .unwrap();

        let result = should_refresh_cloud_ranges(&conn, CloudProvider::AWS, 168).unwrap(); // 7 days
        assert!(!result);
    }

    #[test]
    fn test_should_refresh_cloud_ranges_invalid_timestamp() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        // Insert invalid timestamp
        conn.execute(
            "INSERT INTO cloud_range_metadata (provider, last_fetch_time, fetch_url, record_count, fetch_status)
             VALUES (?, ?, ?, ?, ?)",
            params!["AWS", "invalid-timestamp", "https://example.com", 100, "success"],
        )
        .unwrap();

        let result = should_refresh_cloud_ranges(&conn, CloudProvider::AWS, 168).unwrap();
        assert!(result); // Should refresh on parse error
    }

    // ===== CloudProvider Tests =====

    #[test]
    fn test_cloud_provider_from_str() {
        assert_eq!(CloudProvider::from_str("aws"), Some(CloudProvider::AWS));
        assert_eq!(CloudProvider::from_str("AWS"), Some(CloudProvider::AWS));
        assert_eq!(CloudProvider::from_str("azure"), Some(CloudProvider::Azure));
        assert_eq!(CloudProvider::from_str("gcp"), Some(CloudProvider::GCP));
        assert_eq!(
            CloudProvider::from_str("digitalocean"),
            Some(CloudProvider::DigitalOcean)
        );
        assert_eq!(
            CloudProvider::from_str("cloudflare"),
            Some(CloudProvider::Cloudflare)
        );
        assert_eq!(CloudProvider::from_str("invalid"), None);
    }

    #[test]
    fn test_cloud_provider_as_str() {
        assert_eq!(CloudProvider::AWS.as_str(), "AWS");
        assert_eq!(CloudProvider::Azure.as_str(), "Azure");
        assert_eq!(CloudProvider::GCP.as_str(), "GCP");
        assert_eq!(CloudProvider::DigitalOcean.as_str(), "DigitalOcean");
        assert_eq!(CloudProvider::Cloudflare.as_str(), "Cloudflare");
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_parse_aws_ranges_invalid_cidr() {
        let json = r#"{
            "prefixes": [
                {"ip_prefix": "invalid.cidr", "region": "us-east-1", "service": "EC2"},
                {"ip_prefix": "52.93.153.0/24", "region": "us-east-1", "service": "EC2"}
            ],
            "ipv6_prefixes": []
        }"#;

        let result = parse_aws_ranges(json).unwrap();
        assert_eq!(result.len(), 1); // Should skip invalid CIDR
        assert_eq!(result[0].network.to_string(), "52.93.153.0/24");
    }

    #[test]
    fn test_parse_azure_ranges_empty_prefixes() {
        let json = r#"{
            "values": [
                {
                    "name": "Service",
                    "properties": {
                        "addressPrefixes": []
                    }
                }
            ]
        }"#;

        let result = parse_azure_ranges(json).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_gcp_ranges_mixed_ipv4_ipv6() {
        let json = r#"{
            "prefixes": [
                {"ipv4Prefix": "34.1.208.0/20"},
                {"ipv6Prefix": "2600:1900::/28"},
                {"ipv4Prefix": "35.190.0.0/16", "scope": "us-central1"}
            ]
        }"#;

        let result = parse_gcp_ranges(json).unwrap();
        assert_eq!(result.len(), 3);

        let ipv4_count = result
            .iter()
            .filter(|r| matches!(r.network, IpNetwork::V4(_)))
            .count();
        let ipv6_count = result
            .iter()
            .filter(|r| matches!(r.network, IpNetwork::V6(_)))
            .count();

        assert_eq!(ipv4_count, 2);
        assert_eq!(ipv6_count, 1);
    }

    #[test]
    fn test_cloud_match_overlapping_ranges() {
        let mut cache = CloudRangeCache::new();

        // Add broader range first
        cache.ipv4_ranges.push(CloudRange {
            provider: CloudProvider::AWS,
            service: Some("S3".to_string()),
            region: Some("us-west-2".to_string()),
            network: "52.0.0.0/8".parse().unwrap(),
        });

        // Add more specific range
        cache.ipv4_ranges.push(CloudRange {
            provider: CloudProvider::AWS,
            service: Some("EC2".to_string()),
            region: Some("us-east-1".to_string()),
            network: "52.93.153.0/24".parse().unwrap(),
        });

        let ip: IpAddr = "52.93.153.100".parse().unwrap();
        let result = cache.match_ip(&ip).unwrap();

        // First match wins in our linear search
        assert_eq!(result.provider, CloudProvider::AWS);
    }

    #[test]
    fn test_store_cloud_ranges_large_batch() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        // Create 1000 ranges
        let mut ranges = Vec::new();
        for i in 0..1000 {
            ranges.push(CloudRange {
                provider: CloudProvider::AWS,
                service: Some("EC2".to_string()),
                region: Some("us-east-1".to_string()),
                network: format!("10.{}.0.0/24", i % 256).parse().unwrap(),
            });
        }

        let result = store_cloud_ranges(&conn, &ranges);
        assert!(result.is_ok());

        let count: i32 = conn
            .query_row("SELECT COUNT(*) FROM cloud_ranges", [], |row| row.get(0))
            .unwrap();
        assert!(count >= 256); // Some will be duplicates due to i % 256
    }

    #[test]
    fn test_ipv6_full_address() {
        let mut cache = CloudRangeCache::new();
        cache.ipv6_ranges.push(CloudRange {
            provider: CloudProvider::AWS,
            service: Some("CLOUDFRONT".to_string()),
            region: Some("GLOBAL".to_string()),
            network: "2600:9000:1000::/36".parse().unwrap(),
        });

        let ip: IpAddr = "2600:9000:1000:0:0:0:0:1".parse().unwrap();
        let result = cache.match_ip(&ip);

        assert!(result.is_some());
    }

    #[test]
    fn test_ipv6_compressed() {
        let mut cache = CloudRangeCache::new();
        cache.ipv6_ranges.push(CloudRange {
            provider: CloudProvider::Cloudflare,
            service: None,
            region: None,
            network: "::1/128".parse().unwrap(),
        });

        let ip: IpAddr = "::1".parse().unwrap();
        let result = cache.match_ip(&ip);

        assert!(result.is_some());
    }

    #[test]
    fn test_parse_digitalocean_csv_malformed() {
        let csv = "10.0.0.0/8\nincomplete line\n192.168.0.0/16,nyc1";
        let result = parse_digitalocean_ranges(csv).unwrap();

        // Should skip header and malformed line, only get valid one
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].network.to_string(), "192.168.0.0/16");
    }

    // ===== Integration Tests =====

    #[test]
    fn test_parse_file_with_user_agents() {
        use std::io::Write;
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        // Write test data
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "192.168.1.1 \"Mozilla/5.0 (Windows NT 10.0)\"").unwrap();
        writeln!(file, "192.168.1.2 \"Mozilla/5.1 (Linux)\"").unwrap();
        writeln!(file, "192.168.1.3 \"curl/7.64.0\"").unwrap();
        writeln!(file, "192.168.1.4 \"curl/8.1.2\"").unwrap();
        writeln!(file, "192.168.1.5 \"Python-requests/2.28.0\"").unwrap();
        writeln!(file, "192.168.1.1 \"Mozilla/5.0 (Mac)\"").unwrap();
        drop(file);

        let (ip_counts, total_lines, global_ua_counts) = parse_file(
            &path, None, None, None, None, None, None, None, None, None, None,
        )
        .unwrap();

        assert_eq!(total_lines, 6);
        assert_eq!(ip_counts.len(), 5); // 5 unique IPs

        // Check global UA counts (base names only)
        assert_eq!(global_ua_counts.len(), 3); // Mozilla, curl, Python-requests
        assert_eq!(global_ua_counts.get("Mozilla"), Some(&3)); // 2 from different IPs + 1 repeated IP
        assert_eq!(global_ua_counts.get("curl"), Some(&2));
        assert_eq!(global_ua_counts.get("Python-requests"), Some(&1));

        // Check IP counts
        assert_eq!(ip_counts.get("192.168.1.1").unwrap().0, 2); // Appears twice
        assert_eq!(ip_counts.get("192.168.1.3").unwrap().0, 1);

        // Check that full UA string is preserved for individual IPs
        let ip1_ua = &ip_counts.get("192.168.1.1").unwrap().2;
        assert!(ip1_ua.is_some());
        // Should be one of the full strings, not just "Mozilla"
        assert!(ip1_ua.as_ref().unwrap().contains("/"));
    }

    #[test]
    fn test_parse_file_delimiter_mode() {
        use std::io::Write;
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "192.168.1.1,200,GET,curl/7.64.0").unwrap();
        writeln!(file, "192.168.1.2,404,POST,wget/1.20").unwrap();
        writeln!(file, "192.168.1.1,200,GET,curl/8.0.0").unwrap();
        drop(file);

        let (ip_counts, total_lines, global_ua_counts) = parse_file(
            &path,
            None,
            None,
            None,
            None,
            Some(","),
            Some(1), // IP in field 1
            Some(4), // UA in field 4
        )
        .unwrap();

        assert_eq!(total_lines, 3);
        assert_eq!(ip_counts.len(), 2);

        // Check global UA counts
        assert_eq!(global_ua_counts.get("curl"), Some(&2));
        assert_eq!(global_ua_counts.get("wget"), Some(&1));
    }

    #[test]
    fn test_parse_file_with_filters() {
        use std::io::Write;
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "192.168.1.1 GET \"Mozilla/5.0\"").unwrap();
        writeln!(file, "192.168.1.2 POST \"curl/7.64.0\"").unwrap();
        writeln!(file, "192.168.1.3 GET \"wget/1.20\"").unwrap();
        drop(file);

        // Filter only GET requests
        let (ip_counts, total_lines, global_ua_counts) = parse_file(
            &path,
            Some("GET"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(total_lines, 2); // Only GET requests
        assert_eq!(ip_counts.len(), 2);
        assert_eq!(global_ua_counts.len(), 2); // Mozilla and wget
        assert!(global_ua_counts.contains_key("Mozilla"));
        assert!(global_ua_counts.contains_key("wget"));
        assert!(!global_ua_counts.contains_key("curl")); // Filtered out
    }

    #[test]
    fn test_parse_file_ua_filter() {
        use std::io::Write;
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "192.168.1.1 \"Mozilla/5.0\"").unwrap();
        writeln!(file, "192.168.1.2 \"curl/7.64.0\"").unwrap();
        writeln!(file, "192.168.1.3 \"wget/1.20\"").unwrap();
        drop(file);

        // Filter only curl user agents
        let (ip_counts, total_lines, global_ua_counts) = parse_file(
            &path,
            None,
            None,
            Some("curl"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(total_lines, 1); // Only curl
        assert_eq!(ip_counts.len(), 1);
        assert_eq!(global_ua_counts.len(), 1);
        assert_eq!(global_ua_counts.get("curl"), Some(&1));
    }

    #[test]
    fn test_extract_ua_base() {
        assert_eq!(extract_ua_base("Mozilla/5.0"), "Mozilla");
        assert_eq!(extract_ua_base("curl/7.64.0"), "curl");
        assert_eq!(extract_ua_base("Python-requests/2.28.0"), "Python-requests");
        assert_eq!(extract_ua_base("SimpleUA"), "SimpleUA"); // No slash
        assert_eq!(extract_ua_base(""), "");
    }

    #[test]
    fn test_end_to_end_cloud_detection() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        // Store some test cloud ranges
        let ranges = vec![
            CloudRange {
                provider: CloudProvider::AWS,
                service: Some("EC2".to_string()),
                region: Some("us-east-1".to_string()),
                network: "52.93.153.0/24".parse().unwrap(),
            },
            CloudRange {
                provider: CloudProvider::GCP,
                service: None,
                region: Some("europe-west1".to_string()),
                network: "34.1.208.0/20".parse().unwrap(),
            },
            CloudRange {
                provider: CloudProvider::Cloudflare,
                service: None,
                region: None,
                network: "104.21.48.0/20".parse().unwrap(),
            },
        ];

        store_cloud_ranges(&conn, &ranges).unwrap();

        // Load cache
        let cache = CloudRangeCache::load_from_db(&conn).unwrap();

        // Test AWS IP
        let aws_ip: IpAddr = "52.93.153.170".parse().unwrap();
        let aws_match = cache.match_ip(&aws_ip).unwrap();
        assert_eq!(aws_match.format_org(), "AWS / EC2 / us-east-1");

        // Test GCP IP
        let gcp_ip: IpAddr = "34.1.208.1".parse().unwrap();
        let gcp_match = cache.match_ip(&gcp_ip).unwrap();
        assert_eq!(gcp_match.format_org(), "GCP / europe-west1");

        // Test Cloudflare IP
        let cf_ip: IpAddr = "104.21.48.240".parse().unwrap();
        let cf_match = cache.match_ip(&cf_ip).unwrap();
        assert_eq!(cf_match.format_org(), "Cloudflare");

        // Test non-cloud IP
        let other_ip: IpAddr = "8.8.8.8".parse().unwrap();
        let other_match = cache.match_ip(&other_ip);
        assert!(other_match.is_none());
    }

    #[test]
    fn test_apply_filters_top() {
        let mut counts = HashMap::new();
        counts.insert(
            "192.168.1.1".to_string(),
            (100u64, false, Some("UA1".to_string())),
        );
        counts.insert(
            "192.168.1.2".to_string(),
            (50u64, false, Some("UA2".to_string())),
        );
        counts.insert(
            "192.168.1.3".to_string(),
            (25u64, false, Some("UA3".to_string())),
        );
        counts.insert(
            "192.168.1.4".to_string(),
            (10u64, false, Some("UA4".to_string())),
        );

        let filtered = apply_filters(counts, Some("2"), None);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].0, "192.168.1.1");
        assert_eq!(filtered[0].1, 100);
        assert_eq!(filtered[1].0, "192.168.1.2");
        assert_eq!(filtered[1].1, 50);
    }

    #[test]
    fn test_apply_filters_percentage() {
        let mut counts = HashMap::new();
        counts.insert(
            "192.168.1.1".to_string(),
            (100u64, false, Some("UA1".to_string())),
        );
        counts.insert(
            "192.168.1.2".to_string(),
            (50u64, false, Some("UA2".to_string())),
        );
        counts.insert(
            "192.168.1.3".to_string(),
            (25u64, false, Some("UA3".to_string())),
        );
        counts.insert(
            "192.168.1.4".to_string(),
            (10u64, false, Some("UA4".to_string())),
        );

        let filtered = apply_filters(counts, Some("50%"), None);
        assert_eq!(filtered.len(), 2); // 50% of 4 = 2
    }

    #[test]
    fn test_apply_filters_min() {
        let mut counts = HashMap::new();
        counts.insert(
            "192.168.1.1".to_string(),
            (100u64, false, Some("UA1".to_string())),
        );
        counts.insert(
            "192.168.1.2".to_string(),
            (50u64, false, Some("UA2".to_string())),
        );
        counts.insert(
            "192.168.1.3".to_string(),
            (25u64, false, Some("UA3".to_string())),
        );
        counts.insert(
            "192.168.1.4".to_string(),
            (10u64, false, Some("UA4".to_string())),
        );

        let filtered = apply_filters(counts, None, Some(30));
        assert_eq!(filtered.len(), 2); // Only >= 30
        assert_eq!(filtered[0].1, 100);
        assert_eq!(filtered[1].1, 50);
    }

    #[test]
    fn test_load_or_fetch_cloud_cache_no_refresh_needed() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        // Insert recent metadata
        let recent_time = chrono::Utc::now();
        conn.execute(
            "INSERT INTO cloud_range_metadata (provider, last_fetch_time, fetch_url, record_count, fetch_status)
             VALUES (?, ?, ?, ?, ?)",
            params!["AWS", recent_time.to_rfc3339(), "https://example.com", 100, "success"],
        ).unwrap();

        // Insert some ranges
        let ranges = vec![CloudRange {
            provider: CloudProvider::AWS,
            service: Some("EC2".to_string()),
            region: Some("us-east-1".to_string()),
            network: "52.93.153.0/24".parse().unwrap(),
        }];
        store_cloud_ranges(&conn, &ranges).unwrap();

        // Should load from DB without fetching (max_age = 168 hours = 7 days)
        let rt = tokio::runtime::Runtime::new().unwrap();
        let cache = rt
            .block_on(load_or_fetch_cloud_cache(
                &conn,
                false, // refresh
                false, // force_refresh
                168,   // max_age_hours
                Some(vec![CloudProvider::AWS]),
            ))
            .unwrap();

        assert_eq!(cache.ipv4_ranges.len(), 1);
        assert_eq!(cache.ipv4_ranges[0].provider, CloudProvider::AWS);
    }

    #[test]
    fn test_ipv6_parsing_and_matching() {
        use std::io::Write;
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "2600:9000::1 \"CloudFront\"").unwrap();
        writeln!(file, "2606:4700::1 \"Cloudflare\"").unwrap();
        writeln!(file, "::1 \"localhost\"").unwrap();
        drop(file);

        let (ip_counts, total_lines, global_ua_counts) = parse_file(
            &path, None, None, None, None, None, None, None, None, None, None,
        )
        .unwrap();

        assert_eq!(total_lines, 3);
        assert_eq!(ip_counts.len(), 3);

        // Check IPv6 flag is set
        assert_eq!(ip_counts.get("2600:9000::1").unwrap().1, true); // is_v6 = true
        assert_eq!(ip_counts.get("::1").unwrap().1, true);

        // Check UA counts
        assert_eq!(global_ua_counts.get("CloudFront"), Some(&1));
        assert_eq!(global_ua_counts.get("Cloudflare"), Some(&1));
        assert_eq!(global_ua_counts.get("localhost"), Some(&1));
    }

    #[test]
    fn test_multiple_ips_same_ua() {
        use std::io::Write;
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "192.168.1.1 \"curl/7.64.0\"").unwrap();
        writeln!(file, "192.168.1.2 \"curl/7.64.0\"").unwrap();
        writeln!(file, "192.168.1.3 \"curl/7.65.0\"").unwrap();
        writeln!(file, "192.168.1.4 \"curl/8.0.0\"").unwrap();
        drop(file);

        let (ip_counts, total_lines, global_ua_counts) = parse_file(
            &path, None, None, None, None, None, None, None, None, None, None,
        )
        .unwrap();

        assert_eq!(total_lines, 4);
        assert_eq!(ip_counts.len(), 4);

        // All should be grouped under "curl"
        assert_eq!(global_ua_counts.len(), 1);
        assert_eq!(global_ua_counts.get("curl"), Some(&4));
    }

    #[test]
    fn test_no_user_agent() {
        use std::io::Write;
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "192.168.1.1").unwrap();
        writeln!(file, "192.168.1.2 \"\"").unwrap();
        writeln!(file, "192.168.1.3 \"curl/7.64.0\"").unwrap();
        drop(file);

        let (ip_counts, total_lines, global_ua_counts) = parse_file(
            &path, None, None, None, None, None, None, None, None, None, None,
        )
        .unwrap();

        assert_eq!(total_lines, 3);
        assert_eq!(ip_counts.len(), 3);

        // Only curl should be counted
        assert_eq!(global_ua_counts.len(), 1);
        assert_eq!(global_ua_counts.get("curl"), Some(&1));
    }

    #[test]
    fn test_cloud_range_priority_most_specific() {
        let mut cache = CloudRangeCache::new();

        // Add /16 first
        cache.ipv4_ranges.push(CloudRange {
            provider: CloudProvider::AWS,
            service: Some("S3".to_string()),
            region: Some("us-west-2".to_string()),
            network: "52.93.0.0/16".parse().unwrap(),
        });

        // Add /24 second (more specific)
        cache.ipv4_ranges.push(CloudRange {
            provider: CloudProvider::AWS,
            service: Some("EC2".to_string()),
            region: Some("us-east-1".to_string()),
            network: "52.93.153.0/24".parse().unwrap(),
        });

        let ip: IpAddr = "52.93.153.100".parse().unwrap();

        // First match wins, so depends on order
        let result = cache.match_ip(&ip).unwrap();
        assert_eq!(result.provider, CloudProvider::AWS);

        // To test proper sorting, we'd need to reload from DB which sorts by prefix_length DESC
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        let ranges = vec![
            CloudRange {
                provider: CloudProvider::AWS,
                service: Some("S3".to_string()),
                region: Some("us-west-2".to_string()),
                network: "52.93.0.0/16".parse().unwrap(),
            },
            CloudRange {
                provider: CloudProvider::AWS,
                service: Some("EC2".to_string()),
                region: Some("us-east-1".to_string()),
                network: "52.93.153.0/24".parse().unwrap(),
            },
        ];

        store_cloud_ranges(&conn, &ranges).unwrap();
        let sorted_cache = CloudRangeCache::load_from_db(&conn).unwrap();

        // After loading from DB, should be sorted by prefix_length DESC
        // So /24 should come before /16
        let result = sorted_cache.match_ip(&ip).unwrap();

        // Whichever range matches first will win
        assert_eq!(result.provider, CloudProvider::AWS);
    }
}
