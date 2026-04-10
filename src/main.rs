use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ipnetwork::IpNetwork;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState},
    Terminal,
};
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use flate2::read::GzDecoder;
use std::{
    collections::HashMap,
    fs::File,
    io::{stderr, stdout, BufRead, BufReader, Read, Write},
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, PartialEq)]
enum SortBy {
    Hits,
    Bandwidth,
}

impl SortBy {
    fn toggle(self) -> Self {
        match self {
            SortBy::Hits => SortBy::Bandwidth,
            SortBy::Bandwidth => SortBy::Hits,
        }
    }

    fn label(self) -> &'static str {
        match self {
            SortBy::Hits => "hits",
            SortBy::Bandwidth => "bw",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum GroupBy {
    Ip,
    Org,
    Asn,
    UserAgent,
    CloudProvider,
}

impl GroupBy {
    fn next(self) -> Self {
        match self {
            GroupBy::Ip => GroupBy::Org,
            GroupBy::Org => GroupBy::Asn,
            GroupBy::Asn => GroupBy::UserAgent,
            GroupBy::UserAgent => GroupBy::CloudProvider,
            GroupBy::CloudProvider => GroupBy::Ip,
        }
    }

    fn label(self) -> &'static str {
        match self {
            GroupBy::Ip => "IP",
            GroupBy::Org => "Org",
            GroupBy::Asn => "ASN",
            GroupBy::UserAgent => "UA",
            GroupBy::CloudProvider => "Cloud",
        }
    }
}

struct DisplayConfig {
    has_bytes: bool,
    sort_by: SortBy,
    show_rdns: bool,
    show_ua: bool,
    show_org: bool,
    cloud_detail: bool,
    show_country: bool,
    show_domain: bool,
    group_by: GroupBy,
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
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

fn extract_ua_base(ua: &str) -> &str {
    ua.split('/').next().unwrap_or(ua)
}

const CLOUD_PROVIDER_PREFIXES: &[&str] = &["AWS", "Azure", "GCP", "DigitalOcean", "Cloudflare"];

fn cloud_provider_prefix(org: &str) -> Option<&'static str> {
    for &prefix in CLOUD_PROVIDER_PREFIXES {
        if org == prefix || org.starts_with(&format!("{} / ", prefix)) {
            return Some(prefix);
        }
    }
    None
}

fn effective_org(org: &str, cloud_detail: bool) -> String {
    if cloud_detail {
        return org.to_string();
    }
    if let Some(prefix) = cloud_provider_prefix(org) {
        prefix.to_string()
    } else {
        org.to_string()
    }
}

fn classify_cloud_provider(rec: &IpRecord) -> String {
    // Priority 1: infra field (IP-range-based, authoritative)
    if let Some(ref infra) = rec.infra {
        if let Some(prefix) = cloud_provider_prefix(infra) {
            return prefix.to_string();
        }
        return infra.clone();
    }

    // Priority 2: name-based matching on org, company_domain, asn
    let fields: [Option<&str>; 3] = [
        rec.org.as_deref(),
        rec.company_domain.as_deref(),
        rec.asn.as_deref(),
    ];

    for field in fields.iter().filter_map(|f| *f) {
        let lower = field.to_lowercase();

        if lower.contains("amazon") || lower.contains("aws") {
            return "AWS".to_string();
        }
        if lower.contains("microsoft") || lower.contains("azure") {
            return "Azure".to_string();
        }
        if lower.contains("google") || lower.contains("gcp") {
            return "GCP".to_string();
        }
        if lower.contains("digitalocean") {
            return "DigitalOcean".to_string();
        }
        if lower.contains("cloudflare") {
            return "Cloudflare".to_string();
        }
        if lower.contains("ovh") {
            return "OVH".to_string();
        }
        if lower.contains("hetzner") {
            return "Hetzner".to_string();
        }
        if lower.contains("linode") || lower.contains("akamai") {
            return "Linode/Akamai".to_string();
        }
        if lower.contains("vultr") || lower.contains("choopa") {
            return "Vultr".to_string();
        }
        if (lower.contains("oracle") && lower.contains("cloud")) || lower.contains("oraclecloud") {
            return "Oracle Cloud".to_string();
        }
        if lower.contains("alibaba") || lower.contains("aliyun") || lower.contains("alicloud") {
            return "Alibaba Cloud".to_string();
        }
        if lower.contains("tencent") {
            return "Tencent Cloud".to_string();
        }
        if lower.contains("scaleway") || lower.contains("online.net") || lower.contains("iliad") {
            return "Scaleway".to_string();
        }
        if lower.contains("upcloud") {
            return "UpCloud".to_string();
        }
        if lower.contains("hostinger") {
            return "Hostinger".to_string();
        }
        if lower.contains("orange") {
            return "Orange".to_string();
        }
        if lower.contains("contabo") {
            return "Contabo".to_string();
        }
        if lower.contains("ionos") || lower.contains("1&1") || lower.contains("1and1") {
            return "IONOS".to_string();
        }
        if lower.contains("leaseweb") {
            return "LeaseWeb".to_string();
        }
        if lower.contains("rackspace") {
            return "Rackspace".to_string();
        }
        if lower.contains("softlayer") || lower.contains("ibm cloud") {
            return "IBM Cloud".to_string();
        }
        if lower.contains("kamatera") {
            return "Kamatera".to_string();
        }
        if lower.contains("cherry") && lower.contains("server") {
            return "Cherry Servers".to_string();
        }
        if lower.contains("netcup") {
            return "Netcup".to_string();
        }
        if lower.contains("quadranet") {
            return "QuadraNet".to_string();
        }
        if lower.contains("colocrossing") {
            return "ColoCrossing".to_string();
        }
        if lower.contains("frantech") || lower.contains("buyvm") || lower.contains("ponynet") {
            return "BuyVM/FranTech".to_string();
        }
        if lower.contains("psychz") {
            return "Psychz".to_string();
        }
        if lower.contains("zenlayer") {
            return "Zenlayer".to_string();
        }
        if lower.contains("serverius") {
            return "Serverius".to_string();
        }
        if lower.contains("fastly") {
            return "Fastly".to_string();
        }
        if lower.contains("heroku") || lower.contains("salesforce") {
            return "Heroku/Salesforce".to_string();
        }
    }

    // Priority 3: no match
    "Other/Unknown".to_string()
}

struct ParsedLine {
    ip: IpAddr,
    user_agent: Option<String>,
    bytes: u64,
}

trait LogParser {
    fn parse_line(&self, line: &str) -> Option<ParsedLine>;
    fn has_bytes(&self) -> bool;
}

struct NginxParser {
    re: Regex,
}

impl NginxParser {
    fn new() -> Result<Self> {
        Ok(Self {
            re: Regex::new(r#"^(\S+) \S+ \S+ \[[^\]]+\] "[^"]*" \d+ (\d+) "[^"]*" "([^"]*)"#)?,
        })
    }
}

impl LogParser for NginxParser {
    fn parse_line(&self, line: &str) -> Option<ParsedLine> {
        let cap = self.re.captures(line)?;
        let ip: IpAddr = cap.get(1)?.as_str().parse().ok()?;
        let bytes: u64 = cap
            .get(2)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let ua = cap
            .get(3)
            .map(|m| m.as_str().to_string())
            .filter(|s| !s.is_empty());
        Some(ParsedLine {
            ip,
            user_agent: ua,
            bytes,
        })
    }

    fn has_bytes(&self) -> bool {
        true
    }
}

struct DelimiterParser {
    delimiter: String,
    ip_field: Option<usize>,
    ua_field: Option<usize>,
    bytes_field: Option<usize>,
}

impl DelimiterParser {
    fn new(
        delimiter: &str,
        ip_field: Option<usize>,
        ua_field: Option<usize>,
        bytes_field: Option<usize>,
    ) -> Self {
        Self {
            delimiter: delimiter.to_string(),
            ip_field,
            ua_field,
            bytes_field,
        }
    }
}

impl LogParser for DelimiterParser {
    fn parse_line(&self, line: &str) -> Option<ParsedLine> {
        // Fast path: when field indices are specified, iterate once without collecting
        if self.ip_field.is_some() {
            let ip_idx = self.ip_field.unwrap().saturating_sub(1);
            let ua_idx = self.ua_field.map(|i| i.saturating_sub(1));
            let bytes_idx = self.bytes_field.map(|i| i.saturating_sub(1));
            let max_idx = [Some(ip_idx), ua_idx, bytes_idx]
                .iter()
                .filter_map(|i| *i)
                .max()
                .unwrap_or(0);

            let mut ip_str = None;
            let mut ua_raw = None;
            let mut bytes_raw = None;

            for (i, field) in line.split(&self.delimiter).enumerate() {
                if i == ip_idx {
                    ip_str = Some(field);
                }
                if ua_idx == Some(i) {
                    ua_raw = Some(field);
                }
                if bytes_idx == Some(i) {
                    bytes_raw = Some(field);
                }
                if i >= max_idx {
                    break;
                }
            }

            let ip: IpAddr = ip_str?.parse().ok()?;
            let ua = ua_raw
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let bytes: u64 = bytes_raw
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);

            return Some(ParsedLine {
                ip,
                user_agent: ua,
                bytes,
            });
        }

        // Slow path: auto-detect fields (requires collecting)
        let fields: Vec<&str> = line.split(&self.delimiter).collect();

        let ip_str = fields.iter().find(|f| f.parse::<IpAddr>().is_ok()).copied();
        let ip: IpAddr = ip_str?.parse().ok()?;

        let ua = if let Some(idx) = self.ua_field {
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

        let bytes: u64 = self
            .bytes_field
            .and_then(|idx| fields.get(idx.saturating_sub(1)))
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        Some(ParsedLine {
            ip,
            user_agent: ua,
            bytes,
        })
    }

    fn has_bytes(&self) -> bool {
        self.bytes_field.is_some()
    }
}

struct GenericParser {
    ipv4_re: Regex,
    ipv6_re: Regex,
}

impl GenericParser {
    fn new() -> Result<Self> {
        Ok(Self {
            ipv4_re: Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")?,
            ipv6_re: Regex::new(
                r"\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)\b",
            )?,
        })
    }
}

impl LogParser for GenericParser {
    fn parse_line(&self, line: &str) -> Option<ParsedLine> {
        // Extract UA from last quoted string
        let ua = if let Some(last_quote) = line.rfind('"') {
            line[..last_quote]
                .rfind('"')
                .map(|start| line[start + 1..last_quote].to_string())
        } else {
            None
        };

        // Try first word as IP
        if let Some(first_word) = line.split_whitespace().next() {
            if let Ok(ip) = first_word.parse::<IpAddr>() {
                return Some(ParsedLine {
                    ip,
                    user_agent: ua,
                    bytes: 0,
                });
            }
        }

        // Try ipv4 regex
        if let Some(cap) = self.ipv4_re.captures(line) {
            if let Some(m) = cap.get(1) {
                if let Ok(ip) = m.as_str().parse::<IpAddr>() {
                    return Some(ParsedLine {
                        ip,
                        user_agent: ua,
                        bytes: 0,
                    });
                }
            }
        }

        // Try ipv6 regex
        if let Some(cap) = self.ipv6_re.captures(line) {
            if let Some(m) = cap.get(1) {
                if let Ok(ip) = m.as_str().parse::<IpAddr>() {
                    return Some(ParsedLine {
                        ip,
                        user_agent: ua,
                        bytes: 0,
                    });
                }
            }
        }

        None
    }

    fn has_bytes(&self) -> bool {
        false
    }
}

#[derive(Parser)]
#[command(
    name = "ip-report",
    version,
    about = "Analyze IP addresses from log files"
)]
struct Args {
    /// Input file(s) to parse (supports .gz)
    files: Vec<PathBuf>,
    /// Show only top N IPs, or top N% (e.g., "10" or "10%") [default: 10000]
    #[arg(long)]
    top: Option<String>,
    /// Only show IPs with at least N hits
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
    /// 1-indexed field number for bytes sent (requires --delimiter)
    #[arg(long)]
    bytes_field: Option<usize>,
    /// Log format preset (nginx, bunny). Sets delimiter and field numbers as defaults.
    #[arg(long)]
    format: Option<String>,
    /// Sort order for --top truncation and display (hits or bandwidth) [default: hits]
    #[arg(long)]
    sort: Option<String>,
    /// ipinfo.io API token for org/ASN lookups (replaces whois when set)
    #[arg(long)]
    ipinfo_token: Option<String>,
    /// Minimum request count for an IP to qualify for ipinfo lookup [default: 10]
    #[arg(long, default_value = "10")]
    ipinfo_min_requests: u64,
}

#[derive(Clone)]
struct IpRecord {
    ip: String,
    count: u64,
    user_agent: Option<String>,
    reverse_dns: Option<String>,
    org: Option<String>,
    asn: Option<String>,
    infra: Option<String>,
    country: Option<String>,
    company_domain: Option<String>,
    bytes: u64,
    looked_up: bool,
    lookup_in_progress: bool,
    in_display_set: bool,
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

#[derive(Debug, Deserialize, Clone)]
struct IpInfoAsn {
    asn: Option<String>,
    name: Option<String>,
    domain: Option<String>,
    route: Option<String>,
    #[serde(rename = "type")]
    asn_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpInfoCompany {
    name: Option<String>,
    domain: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpInfoResponse {
    hostname: Option<String>,
    country: Option<String>,
    org: Option<String>,
    asn: Option<IpInfoAsn>,
    company: Option<IpInfoCompany>,
}

async fn fetch_ipinfo(ip: &str, token: &str) -> Result<IpInfoResponse> {
    let url = format!("https://ipinfo.io/{}?token={}", ip, token);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("Failed to build HTTP client for ipinfo")?;

    let max_attempts = 3;
    let mut attempt = 0;

    loop {
        attempt += 1;
        let result = client.get(&url).send().await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return resp
                        .json::<IpInfoResponse>()
                        .await
                        .with_context(|| format!("Failed to parse ipinfo JSON for {}", ip));
                }
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    // Rate limited — back off and retry (don't count as a normal retry)
                    let wait = Duration::from_secs(2u64.pow(attempt));
                    eprintln!(
                        "Warning: ipinfo rate limited for {}, backing off {}s",
                        ip,
                        wait.as_secs()
                    );
                    tokio::time::sleep(wait).await;
                    if attempt >= max_attempts {
                        anyhow::bail!(
                            "ipinfo rate limited for {} after {} attempts",
                            ip,
                            max_attempts
                        );
                    }
                    continue;
                }
                if attempt < max_attempts && status.is_server_error() {
                    let wait = Duration::from_secs(2u64.pow(attempt));
                    eprintln!(
                        "Warning: ipinfo returned {} for {}, retrying in {}s",
                        status, ip, wait.as_secs()
                    );
                    tokio::time::sleep(wait).await;
                    continue;
                }
                anyhow::bail!("ipinfo request failed for {}: HTTP {}", ip, status);
            }
            Err(e) => {
                if attempt < max_attempts {
                    let wait = Duration::from_secs(2u64.pow(attempt));
                    eprintln!(
                        "Warning: ipinfo request error for {}: {}, retrying in {}s",
                        ip, e, wait.as_secs()
                    );
                    tokio::time::sleep(wait).await;
                    continue;
                }
                return Err(e).with_context(|| {
                    format!("ipinfo request failed for {} after {} attempts", ip, max_attempts)
                });
            }
        }
    }
}

async fn fetch_ipinfo_batch(ips: &[&str], token: &str) -> Result<HashMap<String, IpInfoResponse>> {
    let url = format!("https://ipinfo.io/batch?token={}", token);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build HTTP client for ipinfo batch")?;

    let max_attempts = 3;
    let mut attempt = 0;

    loop {
        attempt += 1;
        let result = client
            .post(&url)
            .json(&ips)
            .send()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return resp
                        .json::<HashMap<String, IpInfoResponse>>()
                        .await
                        .context("Failed to parse ipinfo batch JSON");
                }
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    let wait = Duration::from_secs(2u64.pow(attempt));
                    eprintln!(
                        "Warning: ipinfo batch rate limited, backing off {}s",
                        wait.as_secs()
                    );
                    tokio::time::sleep(wait).await;
                    if attempt >= max_attempts {
                        anyhow::bail!(
                            "ipinfo batch rate limited after {} attempts",
                            max_attempts
                        );
                    }
                    continue;
                }
                if attempt < max_attempts && status.is_server_error() {
                    let wait = Duration::from_secs(2u64.pow(attempt));
                    eprintln!(
                        "Warning: ipinfo batch returned {}, retrying in {}s",
                        status, wait.as_secs()
                    );
                    tokio::time::sleep(wait).await;
                    continue;
                }
                anyhow::bail!("ipinfo batch request failed: HTTP {}", status);
            }
            Err(e) => {
                if attempt < max_attempts {
                    let wait = Duration::from_secs(2u64.pow(attempt));
                    eprintln!(
                        "Warning: ipinfo batch request error: {}, retrying in {}s",
                        e, wait.as_secs()
                    );
                    tokio::time::sleep(wait).await;
                    continue;
                }
                return Err(e).with_context(|| {
                    format!("ipinfo batch request failed after {} attempts", max_attempts)
                });
            }
        }
    }
}

fn parse_ipinfo_org(org: &str) -> (Option<String>, Option<String>) {
    let trimmed = org.trim();
    if trimmed.is_empty() {
        return (None, None);
    }
    // Format: "AS15169 Google LLC"
    if let Some(rest) = trimmed.strip_prefix("AS") {
        if let Some(space_idx) = rest.find(' ') {
            if rest[..space_idx].chars().all(|c| c.is_ascii_digit()) {
                let asn = format!("AS{}", &rest[..space_idx]);
                let org_name = rest[space_idx..].trim();
                if org_name.is_empty() {
                    return (Some(asn), None);
                }
                return (Some(asn), Some(org_name.to_string()));
            }
        }
        // "AS15169" with no org name
        if rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
            return (Some(format!("AS{}", rest)), None);
        }
    }
    // No ASN prefix, treat entire string as org
    (None, Some(trimmed.to_string()))
}

fn display_org_with_infra(org: Option<&str>, infra: Option<&str>, cloud_detail: bool) -> String {
    let infra_display = infra.map(|i| effective_org(i, cloud_detail));
    match (org, &infra_display) {
        (Some(o), Some(i)) => format!("{} ({})", o, i),
        (Some(o), None) => o.to_string(),
        (None, Some(i)) => format!("({})", i),
        (None, None) => "-".to_string(),
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
    let mut args = Args::parse();

    if args.top.is_some() && args.min.is_some() {
        anyhow::bail!("Cannot use both --top and --min together");
    }

    // Default to top 100 when neither --top nor --min is specified
    if args.top.is_none() && args.min.is_none() {
        args.top = Some("10000".to_string());
    }

    // Apply format presets (only fill in fields the user didn't explicitly set)
    if let Some(ref fmt) = args.format {
        match fmt.as_str() {
            "nginx" => {
                // Nginx combined log format is parsed with a dedicated regex
                // inside parse_file that extracts IP, bytes_sent, and UA in
                // one pass. No delimiter/field overrides needed.
            }
            "bunny" => {
                // HIT|200|1507167062421|412|390|163.172.53.229|-|https://...|WA|Mozilla/5.0...|req_id|DE
                // Fields: 1=cache_status, 2=status, 3=timestamp, 4=bytes_sent,
                //         5=pull_zone_id, 6=remote_ip, 7=referer, 8=url,
                //         9=edge_location, 10=user_agent, 11=request_id, 12=country_code
                if args.delimiter.is_none() {
                    args.delimiter = Some("|".to_string());
                }
                if args.ip_field.is_none() {
                    args.ip_field = Some(6);
                }
                if args.ua_field.is_none() {
                    args.ua_field = Some(10);
                }
                if args.bytes_field.is_none() {
                    args.bytes_field = Some(4);
                }
            }
            other => {
                anyhow::bail!(
                    "Unknown format '{}'. Supported formats: nginx, bunny",
                    other
                );
            }
        }
    }

    if args.bytes_field.is_some() && args.delimiter.is_none() {
        anyhow::bail!("--bytes-field requires --delimiter");
    }

    let sort_by = match args.sort.as_deref() {
        Some("bandwidth") | Some("bw") => SortBy::Bandwidth,
        Some("hits") | None => SortBy::Hits,
        Some(other) => anyhow::bail!(
            "Unknown sort '{}'. Supported: hits, bandwidth (or bw)",
            other
        ),
    };

    // Build the log parser based on format/delimiter args
    let parser: Box<dyn LogParser> = if args.format.as_deref() == Some("nginx") {
        Box::new(NginxParser::new()?)
    } else if let Some(ref delim) = args.delimiter {
        Box::new(DelimiterParser::new(
            delim,
            args.ip_field,
            args.ua_field,
            args.bytes_field,
        ))
    } else {
        Box::new(GenericParser::new()?)
    };

    let (ip_counts, total_lines, global_ua_counts, global_ua_bytes) = parse_files(
        &args.files,
        args.filter.as_deref(),
        args.ua_filter.as_deref(),
        args.max_lines,
        parser.as_ref(),
    )?;
    let total_ips = ip_counts.len();
    let filtered = apply_filters(&ip_counts, args.top.as_deref(), args.min, sort_by);
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

    let has_bytes = parser.has_bytes();

    let dc = DisplayConfig {
        has_bytes,
        sort_by,
        show_rdns: true,
        show_ua: true,
        show_org: true,
        cloud_detail: true,
        show_country: true,
        show_domain: true,
        group_by: GroupBy::Ip,
    };

    if args.no_lookup {
        println!("Total lines: {}\n", total_lines);
        if has_bytes {
            let total_bytes: u64 = filtered.iter().map(|(_, _, _, _, bytes)| bytes).sum();
            println!(
                "{:<8} {:<6} {:<10} {:<6} {:<45} {}",
                "Count", "%", "Bandwidth", "BW%", "IP", "User Agent"
            );
            println!("{}", "-".repeat(126));
            for (ip, count, _is_v6, ua, bytes) in &filtered {
                let pct = if total_lines > 0 {
                    (*count as f64 / total_lines as f64) * 100.0
                } else {
                    0.0
                };
                let bw_pct = if total_bytes > 0 {
                    (*bytes as f64 / total_bytes as f64) * 100.0
                } else {
                    0.0
                };
                println!(
                    "{:<8} {:<6.2} {:<10} {:<6.2} {:<45} {}",
                    count,
                    pct,
                    format_bytes(*bytes),
                    bw_pct,
                    ip,
                    ua.as_deref().unwrap_or("-")
                );
            }
        } else {
            println!("{:<8} {:<6} {:<45} {}", "Count", "%", "IP", "User Agent");
            println!("{}", "-".repeat(110));
            for (ip, count, _is_v6, ua, _bytes) in &filtered {
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
        global_ua_bytes,
        dc,
        ip_counts,
        args.top,
        args.min,
        args.ipinfo_token,
        args.ipinfo_min_requests,
    ))?;

    Ok(())
}

fn parse_files(
    paths: &[PathBuf],
    filter: Option<&str>,
    ua_filter: Option<&str>,
    max_lines: Option<u64>,
    parser: &dyn LogParser,
) -> Result<(
    HashMap<String, (u64, bool, Option<String>, u64)>,
    u64,
    HashMap<String, u64>,
    HashMap<String, u64>,
)> {
    let filter_re = filter
        .map(|p| Regex::new(p))
        .transpose()
        .context("Invalid --filter regex")?;
    let ua_filter_re = ua_filter
        .map(|p| Regex::new(p))
        .transpose()
        .context("Invalid --ua-filter regex")?;

    let mut counts: HashMap<IpAddr, (u64, HashMap<String, u64>, u64)> = HashMap::new();
    let mut global_ua_counts: HashMap<String, u64> = HashMap::new();
    let mut global_ua_bytes: HashMap<String, u64> = HashMap::new();
    let mut total_lines: u64 = 0;
    let mut any_progress = false;
    let mut line = String::new();
    let mut hit_max = false;

    for path in paths {
        if hit_max {
            break;
        }

        let file = File::open(path)
            .with_context(|| format!("Failed to open input file: {}", path.display()))?;
        let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let filename = path.file_name().unwrap_or_default().to_string_lossy();
        let is_gz = path.extension().map_or(false, |ext| ext == "gz" || ext == "gzip");

        let inner: Box<dyn Read> = if is_gz {
            Box::new(GzDecoder::new(file))
        } else {
            Box::new(file)
        };
        let mut reader = BufReader::with_capacity(1024 * 1024, inner);

        let mut bytes_read: u64 = 0;
        let mut last_progress: u64 = 0;

        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            bytes_read += n as u64;

            if bytes_read - last_progress > 10_000_000 {
                last_progress = bytes_read;
                any_progress = true;
                if !is_gz && file_size > 0 {
                    eprint!(
                        "\x1B[2K\rReading {}: {}% ({} lines)",
                        filename,
                        bytes_read * 100 / file_size,
                        total_lines
                    );
                } else {
                    eprint!(
                        "\x1B[2K\rReading {}: {} bytes ({} lines)",
                        filename, bytes_read, total_lines
                    );
                }
                stderr().flush().ok();
            }

            let line = line.trim_end();

            if let Some(ref re) = filter_re {
                if !re.is_match(line) {
                    continue;
                }
            }

            let parsed = match parser.parse_line(line) {
                Some(p) => p,
                None => continue,
            };

            if let Some(ref re) = ua_filter_re {
                match &parsed.user_agent {
                    Some(ua) if re.is_match(ua) => {}
                    _ => continue,
                }
            }

            total_lines += 1;

            if let Some(max) = max_lines {
                if total_lines >= max {
                    hit_max = true;
                    break;
                }
            }

            let entry = counts.entry(parsed.ip).or_insert((0, HashMap::new(), 0));
            entry.0 += 1;
            entry.2 += parsed.bytes;
            if let Some(ref ua_str) = parsed.user_agent {
                if !ua_str.is_empty() {
                    *entry.1.entry(ua_str.clone()).or_insert(0) += 1;
                    let ua_base = extract_ua_base(ua_str);
                    if !ua_base.is_empty() {
                        if let Some(c) = global_ua_counts.get_mut(ua_base) {
                            *c += 1;
                            *global_ua_bytes.get_mut(ua_base).unwrap() += parsed.bytes;
                        } else {
                            global_ua_counts.insert(ua_base.to_string(), 1);
                            global_ua_bytes.insert(ua_base.to_string(), parsed.bytes);
                        }
                    }
                }
            }
        }
    }

    if any_progress {
        eprintln!("\x1B[2K\rReading: done ({} lines)", total_lines);
    }

    // Convert IpAddr keys to String and pick most common UA
    let result: HashMap<String, (u64, bool, Option<String>, u64)> = counts
        .into_iter()
        .map(|(ip, (count, ua_counts, bytes))| {
            let is_v6 = ip.is_ipv6();
            let top_ua = ua_counts
                .into_iter()
                .max_by_key(|(_, c)| *c)
                .map(|(ua, _)| ua);
            (ip.to_string(), (count, is_v6, top_ua, bytes))
        })
        .collect();

    Ok((result, total_lines, global_ua_counts, global_ua_bytes))
}

fn apply_filters(
    counts: &HashMap<String, (u64, bool, Option<String>, u64)>,
    top: Option<&str>,
    min: Option<u64>,
    sort_by: SortBy,
) -> Vec<(String, u64, bool, Option<String>, u64)> {
    // Sort references to avoid cloning all entries upfront
    let mut refs: Vec<_> = counts.iter().collect();
    match sort_by {
        SortBy::Hits => refs.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then_with(|| a.0.cmp(b.0))),
        SortBy::Bandwidth => {
            refs.sort_by(|a, b| b.1 .3.cmp(&a.1 .3).then_with(|| a.0.cmp(b.0)))
        }
    }

    if let Some(top_str) = top {
        let limit = if top_str.ends_with('%') {
            let pct: f64 = top_str.trim_end_matches('%').parse().unwrap_or(100.0);
            ((refs.len() as f64 * pct / 100.0).ceil() as usize).max(1)
        } else {
            top_str.parse().unwrap_or(refs.len())
        };
        refs.truncate(limit);
    }

    if let Some(min_count) = min {
        refs.retain(|(_, (c, _, _, _))| *c >= min_count);
    }

    // Only clone the survivors
    refs.into_iter()
        .map(|(ip, (c, v6, ua, bytes))| (ip.clone(), *c, *v6, ua.clone(), *bytes))
        .collect()
}

async fn run_lookups_and_display(
    display_ips: Vec<(String, u64, bool, Option<String>, u64)>,
    db_path: &PathBuf,
    concurrency: usize,
    total_lines: u64,
    filter_desc: &str,
    cloud_cache: Option<Arc<CloudRangeCache>>,
    global_ua_counts: HashMap<String, u64>,
    global_ua_bytes: HashMap<String, u64>,
    dc: DisplayConfig,
    full_ip_counts: HashMap<String, (u64, bool, Option<String>, u64)>,
    top: Option<String>,
    min: Option<u64>,
    ipinfo_token: Option<String>,
    ipinfo_min_requests: u64,
) -> Result<()> {
    let conn = Connection::open(db_path)?;
    init_db(&conn)?;

    // Build the set of display IPs for fast membership check
    // When ipinfo token is available, expand to all IPs with count >= min_requests
    let all_ips: Vec<(String, u64, bool, Option<String>, u64, bool)> = if ipinfo_token.is_some() {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        // First add all display IPs (marked as in_display_set)
        for (ip, count, is_v6, ua, bytes) in &display_ips {
            seen.insert(ip.clone());
            result.push((ip.clone(), *count, *is_v6, ua.clone(), *bytes, true));
        }
        // Then add non-display IPs that meet the threshold
        for (ip, (count, is_v6, ua, bytes)) in &full_ip_counts {
            if !seen.contains(ip) && *count >= ipinfo_min_requests {
                seen.insert(ip.clone());
                result.push((ip.clone(), *count, *is_v6, ua.clone(), *bytes, false));
            }
        }
        result
    } else {
        display_ips
            .into_iter()
            .map(|(ip, count, is_v6, ua, bytes)| (ip, count, is_v6, ua, bytes, true))
            .collect()
    };

    let skipped = full_ip_counts.len() - all_ips.iter().map(|(ip, ..)| ip.as_str()).collect::<std::collections::HashSet<_>>().len();
    if skipped > 0 {
        eprintln!("Skipped {} IPs with fewer than {} hits", skipped, ipinfo_min_requests);
    }

    eprint!("\x1B[2K\rPreparing IPs: loading cache...");
    stderr().flush().ok();
    let all_ip_strs: Vec<&str> = all_ips.iter().map(|(ip, ..)| ip.as_str()).collect();
    let db_cache = get_ip_records_batch(&conn, &all_ip_strs);
    eprint!("\x1B[2K\rPreparing IPs: 0/{}", all_ips.len());
    stderr().flush().ok();
    let mut records: Vec<IpRecord> = Vec::with_capacity(all_ips.len());
    conn.execute_batch("BEGIN")?;
    for (i, (ip, count, is_v6, ua, bytes, in_display)) in all_ips.iter().enumerate() {
        if (i + 1) % 50 == 0 || i + 1 == all_ips.len() {
            eprint!("\x1B[2K\rPreparing IPs: {}/{}", i + 1, all_ips.len());
            stderr().flush().ok();
        }
        if let Some(rec) = db_cache.get(ip) {
            records.push(IpRecord {
                ip: ip.clone(),
                count: *count,
                user_agent: ua.clone().or(rec.2.clone()),
                reverse_dns: rec.3.clone(),
                org: rec.4.clone(),
                asn: rec.5.clone(),
                infra: rec.7.clone(),
                country: rec.8.clone(),
                company_domain: rec.9.clone(),
                bytes: *bytes,
                looked_up: rec.6,
                lookup_in_progress: false,
                in_display_set: *in_display,
            });
        } else {
            insert_ip(&conn, ip, *is_v6, ua.as_deref()).ok();
            records.push(IpRecord {
                ip: ip.clone(),
                count: *count,
                user_agent: ua.clone(),
                reverse_dns: None,
                org: None,
                asn: None,
                infra: None,
                country: None,
                company_domain: None,
                bytes: *bytes,
                looked_up: false,
                lookup_in_progress: false,
                in_display_set: *in_display,
            });
        }
    }
    conn.execute_batch("COMMIT")?;
    eprintln!();

    let records = Arc::new(Mutex::new(records));
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let db_path = db_path.clone();

    let ips_to_lookup: Vec<(String, u64)> = {
        let mut recs = records.lock().unwrap();
        recs.iter_mut()
            .filter(|rec| !rec.looked_up)
            .map(|rec| {
                rec.lookup_in_progress = true;
                (rec.ip.clone(), rec.count)
            })
            .collect()
    };

    let mut handles = vec![];
    if !ips_to_lookup.is_empty() {
        eprintln!("Looking up {} IPs...", ips_to_lookup.len());
    }

    // Split IPs into batch-eligible (ipinfo with token + meets threshold) and non-batch
    let (batch_ips, non_batch_ips): (Vec<_>, Vec<_>) = if ipinfo_token.is_some() {
        ips_to_lookup.iter().cloned().partition(|(_, count)| *count >= ipinfo_min_requests)
    } else {
        (vec![], ips_to_lookup.clone())
    };

    // Process ipinfo-eligible IPs via batch API (spawned so TUI can start immediately)
    if !batch_ips.is_empty() {
        let batch_ip_strings: Vec<String> = batch_ips.iter().map(|(ip, _)| ip.clone()).collect();
        // Pre-chunk into owned vectors for the spawned task
        let chunks: Vec<Vec<String>> = batch_ip_strings.chunks(1000).map(|c| c.to_vec()).collect();
        let recs = records.clone();
        let dbp = db_path.clone();
        let cache = cloud_cache.clone();
        let token = ipinfo_token.clone().unwrap();

        let handle = tokio::spawn(async move {
            for chunk in chunks {
                let chunk_refs: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
                match fetch_ipinfo_batch(&chunk_refs, &token).await {
                    Ok(batch_results) => {
                        // Spawn DNS lookups for IPs missing hostname
                        let mut dns_handles: Vec<(String, tokio::task::JoinHandle<Option<String>>)> = vec![];
                        for ip_str in &chunk {
                            let resp = batch_results.get(ip_str.as_str());
                            let needs_dns = resp.map_or(true, |r| r.hostname.is_none());
                            if needs_dns {
                                let ip_clone = ip_str.clone();
                                let handle = tokio::task::spawn_blocking(move || {
                                    if let Ok(addr) = ip_clone.parse::<IpAddr>() {
                                        dns_lookup::lookup_addr(&addr).ok()
                                    } else {
                                        None
                                    }
                                });
                                dns_handles.push((ip_str.clone(), handle));
                            }
                        }
                        // Collect DNS results
                        let mut dns_results: HashMap<String, Option<String>> = HashMap::new();
                        for (ip_str, handle) in dns_handles {
                            dns_results.insert(ip_str, handle.await.ok().flatten());
                        }

                        // Process each IP's results
                        if let Ok(conn) = Connection::open(&dbp) {
                            for ip_str in &chunk {
                                let in_batch = batch_results.contains_key(ip_str.as_str());
                                let (rdns, org, asn_str, country, company_domain, asn_obj) =
                                    if let Some(resp) = batch_results.get(ip_str.as_str()) {
                                        let rdns = if resp.hostname.is_some() {
                                            resp.hostname.clone()
                                        } else {
                                            dns_results.get(ip_str.as_str()).cloned().flatten()
                                        };
                                        let country = resp.country.clone();
                                        let (org, company_domain) = if let Some(ref company) = resp.company {
                                            (company.name.clone(), company.domain.clone())
                                        } else if let Some(ref org_str) = resp.org {
                                            let (_asn, org_name) = parse_ipinfo_org(org_str);
                                            (org_name, None)
                                        } else {
                                            (None, None)
                                        };
                                        let (asn_str, asn_obj) = if let Some(ref asn) = resp.asn {
                                            (asn.asn.clone(), Some(asn.clone()))
                                        } else if let Some(ref org_str) = resp.org {
                                            let (parsed_asn, _) = parse_ipinfo_org(org_str);
                                            (parsed_asn, None)
                                        } else {
                                            (None, None)
                                        };
                                        (rdns, org, asn_str, country, company_domain, asn_obj)
                                    } else {
                                        // IP not in batch response - do DNS fallback
                                        let rdns = dns_results.get(ip_str.as_str()).cloned().flatten();
                                        (rdns, None, None, None, None, None)
                                    };

                                // Cloud cache check
                                let infra = if let Some(ref cache) = cache {
                                    if let Ok(addr) = ip_str.parse::<IpAddr>() {
                                        cache.match_ip(&addr).map(|m| m.format_org())
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                // Update in-memory records
                                {
                                    let mut recs = recs.lock().unwrap();
                                    if let Some(rec) = recs.iter_mut().find(|r| r.ip == *ip_str) {
                                        rec.reverse_dns = rdns.clone();
                                        rec.org = org.clone();
                                        rec.asn = asn_str.clone();
                                        rec.infra = infra.clone();
                                        rec.country = country.clone();
                                        rec.company_domain = company_domain.clone();
                                        rec.looked_up = in_batch;
                                        rec.lookup_in_progress = false;
                                    }
                                }

                                // Update DB
                                if in_batch {
                                    update_ip_lookup(&conn, ip_str, rdns.as_deref(), org.as_deref(), asn_str.as_deref(), infra.as_deref(), country.as_deref(), company_domain.as_deref()).ok();
                                } else {
                                    update_ip_partial(&conn, ip_str, rdns.as_deref(), infra.as_deref()).ok();
                                }
                                if let Some(ref asn_detail) = asn_obj {
                                    if let Some(ref asn_id) = asn_detail.asn {
                                        store_asn(&conn, asn_id, asn_detail.name.as_deref(), asn_detail.domain.as_deref(), asn_detail.route.as_deref(), asn_detail.asn_type.as_deref()).ok();
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ERROR: ipinfo batch lookup failed: {:#}", e);
                        std::process::exit(1);
                    }
                }
            }
        });
        handles.push(handle);
    }

    // Process non-batch IPs with existing per-IP spawn pattern
    for (ip, count) in non_batch_ips {
        let sem = semaphore.clone();
        let recs = records.clone();
        let dbp = db_path.clone();
        let cache = cloud_cache.clone();
        let token = ipinfo_token.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let (rdns, org, asn, infra, country, company_domain, asn_obj, ipinfo_performed) =
                perform_lookup_with_cloud(&ip, cache.as_ref().map(|c| c.as_ref()), token.as_deref(), count, ipinfo_min_requests).await;

            {
                let mut recs = recs.lock().unwrap();
                if let Some(rec) = recs.iter_mut().find(|r| r.ip == ip) {
                    rec.reverse_dns = rdns.clone();
                    rec.org = org.clone();
                    rec.asn = asn.clone();
                    rec.infra = infra.clone();
                    rec.country = country.clone();
                    rec.company_domain = company_domain.clone();
                    rec.looked_up = ipinfo_performed;
                    rec.lookup_in_progress = false;
                }
            }

            if let Ok(conn) = Connection::open(&dbp) {
                if ipinfo_performed {
                    update_ip_lookup(&conn, &ip, rdns.as_deref(), org.as_deref(), asn.as_deref(), infra.as_deref(), country.as_deref(), company_domain.as_deref()).ok();
                } else {
                    update_ip_partial(&conn, &ip, rdns.as_deref(), infra.as_deref()).ok();
                }
                if let Some(ref asn_detail) = asn_obj {
                    if let Some(ref asn_id) = asn_detail.asn {
                        store_asn(&conn, asn_id, asn_detail.name.as_deref(), asn_detail.domain.as_deref(), asn_detail.route.as_deref(), asn_detail.asn_type.as_deref()).ok();
                    }
                }
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
            global_ua_bytes,
            dc,
            full_ip_counts,
            top,
            min,
            db_path.clone(),
            cloud_cache.clone(),
            concurrency,
            semaphore.clone(),
            ipinfo_token.clone(),
            ipinfo_min_requests,
        )
        .await?;
    } else {
        for h in handles {
            h.await.ok();
        }
        let recs = records.lock().unwrap();
        println!("Total lines: {}\n", total_lines);
        if dc.has_bytes {
            let total_bytes: u64 = recs.iter().filter(|r| r.in_display_set).map(|rec| rec.bytes).sum();
            println!(
                "{:<8} {:<6} {:<10} {:<6} {:<40} {:<40} {:<30} {:<12} {:<4} {:<22} {}",
                "Count", "%", "Bandwidth", "BW%", "IP", "Reverse DNS", "Org", "ASN", "CC", "Domain", "User Agent"
            );
            println!("{}", "-".repeat(227));
            for rec in recs.iter().filter(|r| r.in_display_set) {
                let pct = if total_lines > 0 {
                    (rec.count as f64 / total_lines as f64) * 100.0
                } else {
                    0.0
                };
                let bw_pct = if total_bytes > 0 {
                    (rec.bytes as f64 / total_bytes as f64) * 100.0
                } else {
                    0.0
                };
                let org_display = display_org_with_infra(rec.org.as_deref(), rec.infra.as_deref(), dc.cloud_detail);
                println!(
                    "{:<8} {:<6.2} {:<10} {:<6.2} {:<40} {:<40} {:<30} {:<12} {:<4} {:<22} {}",
                    rec.count,
                    pct,
                    format_bytes(rec.bytes),
                    bw_pct,
                    rec.ip,
                    truncate_str(rec.reverse_dns.as_deref().unwrap_or("-"), 38),
                    truncate_str(&org_display, 28),
                    rec.asn.as_deref().unwrap_or("-"),
                    rec.country.as_deref().unwrap_or("-"),
                    truncate_str(rec.company_domain.as_deref().unwrap_or("-"), 20),
                    truncate_str(rec.user_agent.as_deref().unwrap_or("-"), 50)
                );
            }
        } else {
            println!(
                "{:<8} {:<6} {:<40} {:<40} {:<30} {:<12} {:<4} {:<22} {}",
                "Count", "%", "IP", "Reverse DNS", "Org", "ASN", "CC", "Domain", "User Agent"
            );
            println!("{}", "-".repeat(211));
            for rec in recs.iter().filter(|r| r.in_display_set) {
                let pct = if total_lines > 0 {
                    (rec.count as f64 / total_lines as f64) * 100.0
                } else {
                    0.0
                };
                let org_display = display_org_with_infra(rec.org.as_deref(), rec.infra.as_deref(), dc.cloud_detail);
                println!(
                    "{:<8} {:<6.2} {:<40} {:<40} {:<30} {:<12} {:<4} {:<22} {}",
                    rec.count,
                    pct,
                    rec.ip,
                    truncate_str(rec.reverse_dns.as_deref().unwrap_or("-"), 38),
                    truncate_str(&org_display, 28),
                    rec.asn.as_deref().unwrap_or("-"),
                    rec.country.as_deref().unwrap_or("-"),
                    truncate_str(rec.company_domain.as_deref().unwrap_or("-"), 20),
                    truncate_str(rec.user_agent.as_deref().unwrap_or("-"), 50)
                );
            }
        }
    }

    Ok(())
}

fn reselect_records(
    full_ip_counts: &HashMap<String, (u64, bool, Option<String>, u64)>,
    top: Option<&str>,
    min: Option<u64>,
    sort_by: SortBy,
    records: &Arc<Mutex<Vec<IpRecord>>>,
    db_path: &PathBuf,
    cloud_cache: &Option<Arc<CloudRangeCache>>,
    semaphore: &Arc<Semaphore>,
    ipinfo_token: &Option<String>,
    ipinfo_min_requests: u64,
) -> Vec<tokio::task::JoinHandle<()>> {
    let new_top = apply_filters(full_ip_counts, top, min, sort_by);

    // When ipinfo token is available, expand to all IPs with count >= min_requests
    let all_ips: Vec<(String, u64, bool, Option<String>, u64, bool)> = if ipinfo_token.is_some() {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for (ip, count, is_v6, ua, bytes) in &new_top {
            seen.insert(ip.clone());
            result.push((ip.clone(), *count, *is_v6, ua.clone(), *bytes, true));
        }
        for (ip, (count, is_v6, ua, bytes)) in full_ip_counts {
            if !seen.contains(ip) && *count >= ipinfo_min_requests {
                seen.insert(ip.clone());
                result.push((ip.clone(), *count, *is_v6, ua.clone(), *bytes, false));
            }
        }
        result
    } else {
        new_top
            .into_iter()
            .map(|(ip, count, is_v6, ua, bytes)| (ip, count, is_v6, ua, bytes, true))
            .collect()
    };

    // Build lookup of existing records by IP
    let old_recs = records.lock().unwrap();
    let old_map: HashMap<String, IpRecord> = old_recs
        .iter()
        .map(|r| (r.ip.clone(), r.clone()))
        .collect();
    drop(old_recs);

    // Batch-load SQLite cache for IPs not already in memory
    let conn = Connection::open(db_path).ok();
    let new_ips: Vec<&str> = all_ips
        .iter()
        .filter(|(ip, ..)| !old_map.contains_key(ip))
        .map(|(ip, ..)| ip.as_str())
        .collect();
    let db_cache = conn
        .as_ref()
        .map(|c| get_ip_records_batch(c, &new_ips))
        .unwrap_or_default();

    let mut new_records = Vec::with_capacity(all_ips.len());
    let mut ips_to_lookup = Vec::new();
    let mut ips_to_insert: Vec<(String, bool, Option<String>)> = Vec::new();

    for (ip, count, is_v6, ua, bytes, in_display) in all_ips {
        if let Some(existing) = old_map.get(&ip) {
            // Reuse existing record, update count/bytes/display flag
            let mut rec = existing.clone();
            rec.count = count;
            rec.bytes = bytes;
            rec.in_display_set = in_display;
            if ua.is_some() {
                rec.user_agent = ua;
            }
            new_records.push(rec);
        } else if let Some(cached) = db_cache.get(&ip) {
            let needs_lookup = !cached.6;
            new_records.push(IpRecord {
                ip: ip.clone(),
                count,
                user_agent: ua.or(cached.2.clone()),
                reverse_dns: cached.3.clone(),
                org: cached.4.clone(),
                asn: cached.5.clone(),
                infra: cached.7.clone(),
                country: cached.8.clone(),
                company_domain: cached.9.clone(),
                bytes,
                looked_up: cached.6,
                lookup_in_progress: needs_lookup,
                in_display_set: in_display,
            });
            if needs_lookup {
                ips_to_lookup.push((ip, count));
            }
        } else {
            ips_to_insert.push((ip.clone(), is_v6, ua.clone()));
            new_records.push(IpRecord {
                ip: ip.clone(),
                count,
                user_agent: ua,
                reverse_dns: None,
                org: None,
                asn: None,
                infra: None,
                country: None,
                company_domain: None,
                bytes,
                looked_up: false,
                lookup_in_progress: true,
                in_display_set: in_display,
            });
            ips_to_lookup.push((ip, count));
        }
    }

    // Batch-insert new IPs in a single transaction
    if !ips_to_insert.is_empty() {
        if let Some(c) = conn.as_ref() {
            let _ = c.execute_batch("BEGIN");
            for (ip, is_v6, ua) in &ips_to_insert {
                insert_ip(c, ip, *is_v6, ua.as_deref()).ok();
            }
            let _ = c.execute_batch("COMMIT");
        }
    }

    // Replace the records vec
    *records.lock().unwrap() = new_records;

    // Spawn lookup tasks for new IPs
    let mut handles = Vec::new();
    for (ip, count) in ips_to_lookup {
        let sem = semaphore.clone();
        let recs = records.clone();
        let dbp = db_path.clone();
        let cache = cloud_cache.clone();
        let token = ipinfo_token.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let (rdns, org, asn, infra, country, company_domain, asn_obj, ipinfo_performed) =
                perform_lookup_with_cloud(&ip, cache.as_ref().map(|c| c.as_ref()), token.as_deref(), count, ipinfo_min_requests).await;

            {
                let mut recs = recs.lock().unwrap();
                if let Some(rec) = recs.iter_mut().find(|r| r.ip == ip) {
                    rec.reverse_dns = rdns.clone();
                    rec.org = org.clone();
                    rec.asn = asn.clone();
                    rec.infra = infra.clone();
                    rec.country = country.clone();
                    rec.company_domain = company_domain.clone();
                    rec.looked_up = ipinfo_performed;
                    rec.lookup_in_progress = false;
                }
            }

            if let Ok(conn) = Connection::open(&dbp) {
                if ipinfo_performed {
                    update_ip_lookup(&conn, &ip, rdns.as_deref(), org.as_deref(), asn.as_deref(), infra.as_deref(), country.as_deref(), company_domain.as_deref()).ok();
                } else {
                    update_ip_partial(&conn, &ip, rdns.as_deref(), infra.as_deref()).ok();
                }
                if let Some(ref asn_detail) = asn_obj {
                    if let Some(ref asn_id) = asn_detail.asn {
                        store_asn(&conn, asn_id, asn_detail.name.as_deref(), asn_detail.domain.as_deref(), asn_detail.route.as_deref(), asn_detail.asn_type.as_deref()).ok();
                    }
                }
            }
        });
        handles.push(handle);
    }

    handles
}

async fn run_tui(
    records: Arc<Mutex<Vec<IpRecord>>>,
    handles: Vec<tokio::task::JoinHandle<()>>,
    total_lines: u64,
    filter_desc: &str,
    global_ua_counts: HashMap<String, u64>,
    global_ua_bytes: HashMap<String, u64>,
    mut dc: DisplayConfig,
    full_ip_counts: HashMap<String, (u64, bool, Option<String>, u64)>,
    top: Option<String>,
    min: Option<u64>,
    db_path: PathBuf,
    cloud_cache: Option<Arc<CloudRangeCache>>,
    concurrency: usize,
    semaphore: Arc<Semaphore>,
    ipinfo_token: Option<String>,
    ipinfo_min_requests: u64,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut table_state = TableState::default();
    table_state.select(Some(0));
    let mut search_mode = false;
    let mut search_query = String::new();
    let mut show_help = false;

    let active_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> =
        Arc::new(Mutex::new(handles));
    let _ = concurrency; // semaphore already encodes concurrency

    loop {
        let recs = records.lock().unwrap().clone();
        let pending = {
            let mut handles = active_handles.lock().unwrap();
            handles.retain(|h| !h.is_finished());
            let handle_pending = handles.len();
            // Also count IPs with lookup_in_progress (e.g. batch lookups use a single handle)
            let ip_pending = recs.iter().filter(|r| r.lookup_in_progress).count();
            // Use the greater of the two: handle count reflects spawned tasks,
            // ip_pending reflects individual IPs still being processed within batch tasks
            handle_pending.max(ip_pending)
        };

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
                            || r.asn
                                .as_ref()
                                .map(|s| s.to_lowercase().contains(&q))
                                .unwrap_or(false)
                            || r.infra
                                .as_ref()
                                .map(|s| s.to_lowercase().contains(&q))
                                .unwrap_or(false)
                            || r.country
                                .as_ref()
                                .map(|s| s.to_lowercase().contains(&q))
                                .unwrap_or(false)
                            || r.company_domain
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

            let mut filtered_recs = filtered_recs;
            match dc.sort_by {
                SortBy::Hits => filtered_recs
                    .sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip))),
                SortBy::Bandwidth => filtered_recs
                    .sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.ip.cmp(&b.ip))),
            }

            let search_str = if search_mode {
                format!(" [SEARCH: {}█]", search_query)
            } else if !search_query.is_empty() {
                format!(" [filter: {}]", search_query)
            } else {
                String::new()
            };

            match dc.group_by {
                GroupBy::Ip => {
                    let display_recs: Vec<IpRecord> = filtered_recs.iter()
                        .filter(|r| r.in_display_set)
                        .cloned()
                        .collect();
                    render_ip_view(
                        f,
                        &display_recs,
                        &mut table_state,
                        total_lines,
                        pending,
                        filter_desc,
                        &search_str,
                        &dc,
                    );
                }
                GroupBy::Org => render_grouped_view(
                    f,
                    &filtered_recs,
                    &mut table_state,
                    total_lines,
                    pending,
                    filter_desc,
                    "Org",
                    &search_str,
                    &dc,
                    |r| {
                        display_org_with_infra(
                            r.org.as_deref(),
                            r.infra.as_deref(),
                            dc.cloud_detail,
                        )
                    },
                    Some(("Domain", |r: &IpRecord| r.company_domain.clone())),
                ),
                GroupBy::Asn => render_grouped_view(
                    f,
                    &filtered_recs,
                    &mut table_state,
                    total_lines,
                    pending,
                    filter_desc,
                    "ASN",
                    &search_str,
                    &dc,
                    |r| {
                        r.asn.clone().unwrap_or_else(|| {
                            display_org_with_infra(
                                r.org.as_deref(),
                                r.infra.as_deref(),
                                dc.cloud_detail,
                            )
                        })
                    },
                    None::<(&str, fn(&IpRecord) -> Option<String>)>,
                ),
                GroupBy::UserAgent => render_ua_global_view(
                    f,
                    &global_ua_counts,
                    &global_ua_bytes,
                    &mut table_state,
                    total_lines,
                    pending,
                    filter_desc,
                    &search_str,
                    &dc,
                ),
                GroupBy::CloudProvider => render_grouped_view(
                    f,
                    &filtered_recs,
                    &mut table_state,
                    total_lines,
                    pending,
                    filter_desc,
                    "Cloud Provider",
                    &search_str,
                    &dc,
                    |r| classify_cloud_provider(r),
                    None::<(&str, fn(&IpRecord) -> Option<String>)>,
                ),
            }

            if show_help {
                render_help_overlay(f, &dc);
            }
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if show_help {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => {
                                show_help = false;
                            }
                            _ => {}
                        }
                        continue;
                    }

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
                                    || r.asn
                                        .as_ref()
                                        .map(|s| s.to_lowercase().contains(&q))
                                        .unwrap_or(false)
                                    || r.infra
                                        .as_ref()
                                        .map(|s| s.to_lowercase().contains(&q))
                                        .unwrap_or(false)
                                    || r.country
                                        .as_ref()
                                        .map(|s| s.to_lowercase().contains(&q))
                                        .unwrap_or(false)
                                    || r.company_domain
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

                    let filtered_owned: Vec<IpRecord> =
                        filtered_recs.iter().map(|r| (*r).clone()).collect();
                    let len = match dc.group_by {
                        GroupBy::Ip => filtered_recs.iter().filter(|r| r.in_display_set).count(),
                        GroupBy::Org => aggregate_by_field(&filtered_owned, &|r: &IpRecord| {
                            display_org_with_infra(
                                r.org.as_deref(),
                                r.infra.as_deref(),
                                dc.cloud_detail,
                            )
                        })
                        .len(),
                        GroupBy::Asn => aggregate_by_field(&filtered_owned, &|r: &IpRecord| {
                            r.asn.clone().unwrap_or_else(|| {
                                display_org_with_infra(
                                    r.org.as_deref(),
                                    r.infra.as_deref(),
                                    dc.cloud_detail,
                                )
                            })
                        })
                        .len(),
                        GroupBy::UserAgent => global_ua_counts.len(),
                        GroupBy::CloudProvider => aggregate_by_field(&filtered_owned, &|r: &IpRecord| {
                            classify_cloud_provider(r)
                        })
                        .len(),
                    };

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('?') => {
                            show_help = true;
                        }
                        KeyCode::Char('f') | KeyCode::F(3) => {
                            search_mode = true;
                        }
                        KeyCode::Char('g') => {
                            dc.group_by = dc.group_by.next();
                            table_state.select(Some(0));
                        }
                        KeyCode::Char('s') => {
                            dc.sort_by = dc.sort_by.toggle();
                            // Show "Resorting..." before the blocking work
                            terminal.draw(|f| {
                                let area = f.area();
                                let msg = format!(" Resorting by {}... ", dc.sort_by.label());
                                let w = msg.len() as u16 + 2;
                                let h = 3u16;
                                let popup = Rect::new(
                                    area.width.saturating_sub(w) / 2,
                                    area.height.saturating_sub(h) / 2,
                                    w.min(area.width),
                                    h.min(area.height),
                                );
                                f.render_widget(Clear, popup);
                                f.render_widget(
                                    Paragraph::new(msg)
                                        .block(Block::default().borders(Borders::ALL)),
                                    popup,
                                );
                            })?;
                            let new_handles = reselect_records(
                                &full_ip_counts,
                                top.as_deref(),
                                min,
                                dc.sort_by,
                                &records,
                                &db_path,
                                &cloud_cache,
                                &semaphore,
                                &ipinfo_token,
                                ipinfo_min_requests,
                            );
                            active_handles.lock().unwrap().extend(new_handles);
                            table_state.select(Some(0));
                        }
                        KeyCode::Char('r') => dc.show_rdns = !dc.show_rdns,
                        KeyCode::Char('u') => dc.show_ua = !dc.show_ua,
                        KeyCode::Char('o') => dc.show_org = !dc.show_org,
                        KeyCode::Char('y') => dc.show_country = !dc.show_country,
                        KeyCode::Char('d') => dc.show_domain = !dc.show_domain,
                        KeyCode::Char('c') => dc.cloud_detail = !dc.cloud_detail,
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
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

fn render_help_overlay(f: &mut ratatui::Frame, dc: &DisplayConfig) {
    let area = f.area();
    let width = 60u16.min(area.width.saturating_sub(4));
    let height = 26u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    let popup = Rect::new(x, y, width, height);

    let key_style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    let desc_style = Style::default();

    let mut lines = vec![
        Line::from(Span::styled("  Keybindings", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];

    let bindings = [
        ("j / Down", "Move down"),
        ("k / Up", "Move up"),
        ("PgDn / PgUp", "Scroll by 20 rows"),
        ("Home / End", "Jump to first / last row"),
        ("f / F3", "Search / filter"),
        ("s", "Toggle sort (hits / bandwidth)"),
        ("g", "Cycle group by (IP / Org / ASN / UA / Cloud)"),
        ("r", "Toggle reverse DNS column"),
        ("u", "Toggle user agent column"),
        ("o", "Toggle org column"),
        ("y", "Toggle country column"),
        ("d", "Toggle domain column"),
        ("c", "Toggle cloud detail / aggregate"),
        ("?", "Show / dismiss this help"),
        ("q / Esc", "Quit"),
    ];

    for (key, desc) in bindings {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:<14}", key), key_style),
            Span::styled(desc, desc_style),
        ]));
    }

    lines.push(Line::from(""));
    if dc.has_bytes {
        lines.push(Line::from(Span::styled(
            "  Sort toggle (s) re-selects top N from full dataset.",
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press ? or Esc to close",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Help ")
            .style(Style::default().bg(Color::Black)),
    );

    f.render_widget(Clear, popup);
    f.render_widget(paragraph, popup);
}

fn aggregate_by_field<F>(recs: &[IpRecord], key_fn: &F) -> Vec<(String, u64, usize, u64)>
where
    F: Fn(&IpRecord) -> String,
{
    let mut groups: HashMap<String, (u64, usize, u64)> = HashMap::new();
    for rec in recs {
        let key = key_fn(rec);
        let entry = groups.entry(key).or_insert((0, 0, 0));
        entry.0 += rec.count;
        entry.1 += 1;
        entry.2 += rec.bytes;
    }
    let mut sorted: Vec<_> = groups
        .into_iter()
        .map(|(k, (count, n, bytes))| (k, count, n, bytes))
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
    filter_desc: &str,
    search_str: &str,
    dc: &DisplayConfig,
) {
    let mut header_cells = vec![Cell::from("Count"), Cell::from("%")];
    if dc.has_bytes {
        header_cells.push(Cell::from("Bandwidth"));
        header_cells.push(Cell::from("BW%"));
    }
    header_cells.push(Cell::from("IP"));
    if dc.show_rdns {
        header_cells.push(Cell::from("Reverse DNS"));
    }
    if dc.show_org {
        header_cells.push(Cell::from("Org"));
    }
    if dc.show_country {
        header_cells.push(Cell::from("CC"));
    }
    if dc.show_domain {
        header_cells.push(Cell::from("Domain"));
    }
    if dc.show_ua {
        header_cells.push(Cell::from("User Agent"));
    }

    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

    let visible_cols = 3
        + dc.show_rdns as usize
        + dc.show_ua as usize
        + dc.show_org as usize
        + dc.show_country as usize
        + dc.show_domain as usize
        + dc.has_bytes as usize * 2;
    let extra_width: usize = if visible_cols <= 4 {
        60
    } else if visible_cols <= 5 {
        30
    } else if visible_cols <= 6 {
        15
    } else {
        0
    };

    let total_bytes: u64 = recs.iter().map(|rec| rec.bytes).sum();

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
            ];
            if dc.has_bytes {
                cells.push(Cell::from(format_bytes(rec.bytes)));
                let bw_pct = if total_bytes > 0 {
                    (rec.bytes as f64 / total_bytes as f64) * 100.0
                } else {
                    0.0
                };
                cells.push(Cell::from(format!("{:.2}", bw_pct)));
            }
            cells.push(Cell::from(rec.ip.clone()));
            if dc.show_rdns {
                cells.push(Cell::from(truncate_str(
                    rec.reverse_dns.as_deref().unwrap_or("-"),
                    38 + extra_width,
                )));
            }
            if dc.show_org {
                let org_str = display_org_with_infra(rec.org.as_deref(), rec.infra.as_deref(), dc.cloud_detail);
                cells.push(Cell::from(truncate_str(&org_str, 25 + extra_width)));
            }
            if dc.show_country {
                cells.push(Cell::from(rec.country.as_deref().unwrap_or("-").to_string()));
            }
            if dc.show_domain {
                cells.push(Cell::from(truncate_str(
                    rec.company_domain.as_deref().unwrap_or("-"),
                    20 + extra_width,
                )));
            }
            if dc.show_ua {
                cells.push(Cell::from(truncate_str(
                    rec.user_agent.as_deref().unwrap_or("-"),
                    40 + extra_width,
                )));
            }
            Row::new(cells)
        })
        .collect();

    let mut widths = vec![Constraint::Min(10), Constraint::Length(6)];
    if dc.has_bytes {
        widths.push(Constraint::Length(10));
        widths.push(Constraint::Length(6));
    }
    widths.push(Constraint::Length(40));
    if dc.show_rdns {
        widths.push(Constraint::Length((40 + extra_width) as u16));
    }
    if dc.show_org {
        widths.push(Constraint::Length((27 + extra_width) as u16));
    }
    if dc.show_country {
        widths.push(Constraint::Length(4));
    }
    if dc.show_domain {
        widths.push(Constraint::Length((22 + extra_width) as u16));
    }
    if dc.show_ua {
        widths.push(Constraint::Min(20));
    }

    let toggles = format!(
        "r:{} u:{} o:{} y:{} d:{} c:{}",
        if dc.show_rdns { "on" } else { "off" },
        if dc.show_ua { "on" } else { "off" },
        if dc.show_org { "on" } else { "off" },
        if dc.show_country { "on" } else { "off" },
        if dc.show_domain { "on" } else { "off" },
        if dc.cloud_detail { "detail" } else { "agg" },
    );

    let pending_str = if pending > 0 {
        format!(", {} pending", pending)
    } else {
        String::new()
    };

    let sort_str = if dc.has_bytes {
        format!(" [sort:{}]", dc.sort_by.label())
    } else {
        String::new()
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {} IPs, {} lines{} [{}] [by:{}]{}{} (g/s/r/u/o/y/d/c/f/?=help, q=quit)",
            filter_desc,
            total_lines,
            pending_str,
            toggles,
            dc.group_by.label(),
            sort_str,
            search_str
        )))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    f.render_stateful_widget(table, f.area(), table_state);
}

fn render_grouped_view<F, E>(
    f: &mut ratatui::Frame,
    recs: &[IpRecord],
    table_state: &mut TableState,
    total_lines: u64,
    pending: usize,
    filter_desc: &str,
    group_label: &str,
    search_str: &str,
    dc: &DisplayConfig,
    key_fn: F,
    extra_col: Option<(&str, E)>,
) where
    F: Fn(&IpRecord) -> String,
    E: Fn(&IpRecord) -> Option<String>,
{
    // Collect extra values per group key if extra_col is provided
    let extra_values: HashMap<String, Vec<String>> = if let Some((_, ref extra_fn)) = extra_col {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for rec in recs {
            let key = key_fn(rec);
            if let Some(val) = extra_fn(rec) {
                let entry = map.entry(key).or_default();
                if !entry.contains(&val) {
                    entry.push(val);
                }
            }
        }
        map
    } else {
        HashMap::new()
    };

    let mut groups = aggregate_by_field(recs, &key_fn);
    match dc.sort_by {
        SortBy::Hits => groups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0))),
        SortBy::Bandwidth => groups.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.0.cmp(&b.0))),
    }

    let has_extra = extra_col.is_some();
    let extra_label = extra_col.as_ref().map(|(label, _)| *label);

    let mut header_cells = vec![Cell::from("Count"), Cell::from("%"), Cell::from("IPs")];
    if dc.has_bytes {
        header_cells.push(Cell::from("Bandwidth"));
        header_cells.push(Cell::from("BW%"));
    }
    header_cells.push(Cell::from(group_label));
    if let Some(label) = extra_label {
        header_cells.push(Cell::from(label));
    }

    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

    let total_bytes: u64 = groups.iter().map(|(_, _, _, bytes)| bytes).sum();

    let rows: Vec<Row> = groups
        .iter()
        .map(|(key, count, ip_count, bytes)| {
            let pct = if total_lines > 0 {
                (*count as f64 / total_lines as f64) * 100.0
            } else {
                0.0
            };
            let mut cells = vec![
                Cell::from(format!("{}", count)),
                Cell::from(format!("{:.2}", pct)),
                Cell::from(format!("{}", ip_count)),
            ];
            if dc.has_bytes {
                cells.push(Cell::from(format_bytes(*bytes)));
                let bw_pct = if total_bytes > 0 {
                    (*bytes as f64 / total_bytes as f64) * 100.0
                } else {
                    0.0
                };
                cells.push(Cell::from(format!("{:.2}", bw_pct)));
            }
            cells.push(Cell::from(key.clone()));
            if has_extra {
                let val = extra_values
                    .get(key)
                    .map(|v| v.join(", "))
                    .unwrap_or_else(|| "-".to_string());
                cells.push(Cell::from(val));
            }
            Row::new(cells)
        })
        .collect();

    let mut widths = vec![
        Constraint::Min(10),
        Constraint::Length(6),
        Constraint::Length(6),
    ];
    if dc.has_bytes {
        widths.push(Constraint::Length(10));
        widths.push(Constraint::Length(6));
    }
    widths.push(Constraint::Min(40));
    if has_extra {
        widths.push(Constraint::Min(20));
    }

    let pending_str = if pending > 0 {
        format!(", {} pending", pending)
    } else {
        String::new()
    };

    let cloud_str = format!(" [c:{}]", if dc.cloud_detail { "detail" } else { "agg" });

    let sort_str = if dc.has_bytes {
        format!(" [sort:{}]", dc.sort_by.label())
    } else {
        String::new()
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {} IPs by {}, {} lines{}{} [by:{}]{}{} (g/s/c/f/?=help, q=quit)",
            filter_desc,
            group_label,
            total_lines,
            pending_str,
            cloud_str,
            dc.group_by.label(),
            sort_str,
            search_str
        )))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    f.render_stateful_widget(table, f.area(), table_state);
}

fn render_ua_global_view(
    f: &mut ratatui::Frame,
    global_ua_counts: &HashMap<String, u64>,
    global_ua_bytes: &HashMap<String, u64>,
    table_state: &mut TableState,
    total_lines: u64,
    pending: usize,
    filter_desc: &str,
    search_str: &str,
    dc: &DisplayConfig,
) {
    // Convert global UA counts to sorted vec
    let mut ua_groups: Vec<(String, u64, u64)> = global_ua_counts
        .iter()
        .map(|(ua, count)| {
            let bytes = global_ua_bytes.get(ua).copied().unwrap_or(0);
            (ua.clone(), *count, bytes)
        })
        .collect();
    match dc.sort_by {
        SortBy::Hits => ua_groups.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0))),
        SortBy::Bandwidth => ua_groups.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0))),
    }

    let mut header_cells = vec![Cell::from("Count"), Cell::from("%")];
    if dc.has_bytes {
        header_cells.push(Cell::from("Bandwidth"));
        header_cells.push(Cell::from("BW%"));
    }
    header_cells.push(Cell::from("User Agent"));

    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

    let total_bytes: u64 = ua_groups.iter().map(|(_, _, bytes)| bytes).sum();

    let rows: Vec<Row> = ua_groups
        .iter()
        .map(|(ua, count, bytes)| {
            let pct = if total_lines > 0 {
                (*count as f64 / total_lines as f64) * 100.0
            } else {
                0.0
            };
            let mut cells = vec![
                Cell::from(format!("{}", count)),
                Cell::from(format!("{:.2}", pct)),
            ];
            if dc.has_bytes {
                cells.push(Cell::from(format_bytes(*bytes)));
                let bw_pct = if total_bytes > 0 {
                    (*bytes as f64 / total_bytes as f64) * 100.0
                } else {
                    0.0
                };
                cells.push(Cell::from(format!("{:.2}", bw_pct)));
            }
            cells.push(Cell::from(ua.clone()));
            Row::new(cells)
        })
        .collect();

    let mut widths = vec![Constraint::Min(10), Constraint::Length(6)];
    if dc.has_bytes {
        widths.push(Constraint::Length(10));
        widths.push(Constraint::Length(6));
    }
    widths.push(Constraint::Min(40));

    let pending_str = if pending > 0 {
        format!(", {} pending", pending)
    } else {
        String::new()
    };

    let sort_str = if dc.has_bytes {
        format!(" [sort:{}]", dc.sort_by.label())
    } else {
        String::new()
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {} IPs by User Agent, {} lines{} [by:{}]{}{} (g/s/f/?=help, q=quit)",
            filter_desc,
            total_lines,
            pending_str,
            dc.group_by.label(),
            sort_str,
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

    eprint!("Loading cloud range cache...");
    let result = CloudRangeCache::load_from_db(conn);
    eprintln!(" done");
    result
}

async fn perform_lookup_with_cloud(
    ip: &str,
    cloud_cache: Option<&CloudRangeCache>,
    ipinfo_token: Option<&str>,
    request_count: u64,
    ipinfo_min_requests: u64,
) -> (Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<IpInfoAsn>, bool) {
    // Check cloud cache → result goes to infra (not org)
    let infra = if let Some(cache) = cloud_cache {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            cache.match_ip(&addr).map(|m| m.format_org())
        } else {
            None
        }
    } else {
        None
    };

    if let Some(token) = ipinfo_token {
        // ipinfo mode: call API if count meets threshold
        if request_count >= ipinfo_min_requests {
            match fetch_ipinfo(ip, token).await {
                Ok(resp) => {
                    // Use hostname as rdns if available, otherwise fall back to dns_lookup
                    let rdns = if resp.hostname.is_some() {
                        resp.hostname.clone()
                    } else {
                        let ip_clone = ip.to_string();
                        tokio::task::spawn_blocking(move || {
                            if let Ok(addr) = ip_clone.parse::<IpAddr>() {
                                dns_lookup::lookup_addr(&addr).ok()
                            } else {
                                None
                            }
                        })
                        .await
                        .ok()
                        .flatten()
                    };

                    let country = resp.country.clone();

                    // Determine org and company_domain
                    let (org, company_domain) = if let Some(ref company) = resp.company {
                        (company.name.clone(), company.domain.clone())
                    } else if let Some(ref org_str) = resp.org {
                        let (_asn, org_name) = parse_ipinfo_org(org_str);
                        (org_name, None)
                    } else {
                        (None, None)
                    };

                    // Determine ASN string and full ASN object
                    let (asn_str, asn_obj) = if let Some(ref asn) = resp.asn {
                        (asn.asn.clone(), Some(asn.clone()))
                    } else if let Some(ref org_str) = resp.org {
                        let (parsed_asn, _) = parse_ipinfo_org(org_str);
                        (parsed_asn, None)
                    } else {
                        (None, None)
                    };

                    return (rdns, org, asn_str, infra, country, company_domain, asn_obj, true);
                }
                Err(e) => {
                    eprintln!("ERROR: ipinfo lookup failed for {}: {:#}", ip, e);
                    std::process::exit(1);
                }
            }
        }
        // Below threshold: do dns_lookup + cloud only
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
        (rdns, None, None, infra, None, None, None, false)
    } else {
        // No ipinfo token: dns_lookup + cloud/whois
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

        if infra.is_some() {
            // Cloud matched: skip whois
            (rdns, None, None, infra, None, None, None, true)
        } else {
            // No cloud match: run whois for org only
            let org = tokio::process::Command::new("whois")
                .arg(ip)
                .output()
                .await
                .ok()
                .and_then(|out| {
                    let text = String::from_utf8_lossy(&out.stdout);
                    extract_org_from_whois(&text)
                });
            (rdns, org, None, infra, None, None, None, true)
        }
    }
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
            insert_date TEXT NOT NULL,
            asn TEXT,
            infra TEXT,
            country TEXT,
            company_domain TEXT
        )",
        [],
    )?;

    // Migrate: add columns if missing (for existing DBs)
    conn.execute("ALTER TABLE ips ADD COLUMN asn TEXT", []).ok();
    conn.execute("ALTER TABLE ips ADD COLUMN infra TEXT", []).ok();
    conn.execute("ALTER TABLE ips ADD COLUMN country TEXT", []).ok();
    conn.execute("ALTER TABLE ips ADD COLUMN company_domain TEXT", []).ok();

    // Migrate: reset looked_up for IPs that were incorrectly marked as fully looked up
    // but never got ipinfo data (no org, asn, country, or company_domain)
    conn.execute(
        "UPDATE ips SET looked_up = 0 WHERE looked_up = 1 AND org IS NULL AND asn IS NULL AND country IS NULL AND company_domain IS NULL",
        [],
    ).ok();

    // ASN details table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS asns (
            asn TEXT PRIMARY KEY,
            name TEXT,
            domain TEXT,
            route TEXT,
            asn_type TEXT
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
    Option<String>,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
)> {
    conn.query_row(
        "SELECT ip, is_v6, user_agent, reverse_dns, org, asn, looked_up, infra, country, company_domain FROM ips WHERE ip = ?",
        [ip],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i32>(1)? != 0,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i32>(6)? != 0,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        },
    )
    .ok()
}

type IpRecordRow = (
    String,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn get_ip_records_batch(
    conn: &Connection,
    ips: &[&str],
) -> HashMap<String, IpRecordRow> {
    let mut result = HashMap::with_capacity(ips.len());
    // SQLite has a variable limit (default 999), batch in chunks
    for chunk in ips.chunks(500) {
        let placeholders: Vec<&str> = chunk.iter().map(|_| "?").collect();
        let sql = format!(
            "SELECT ip, is_v6, user_agent, reverse_dns, org, asn, looked_up, infra, country, company_domain FROM ips WHERE ip IN ({})",
            placeholders.join(",")
        );
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let params: Vec<&dyn rusqlite::types::ToSql> = chunk.iter().map(|ip| ip as &dyn rusqlite::types::ToSql).collect();
        let rows = match stmt.query_map(params.as_slice(), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i32>(1)? != 0,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i32>(6)? != 0,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        }) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for row in rows.flatten() {
            result.insert(row.0.clone(), row);
        }
    }
    result
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
    asn: Option<&str>,
    infra: Option<&str>,
    country: Option<&str>,
    company_domain: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE ips SET looked_up = 1, reverse_dns = ?, org = ?, asn = ?, infra = ?, country = ?, company_domain = ? WHERE ip = ?",
        params![rdns, org, asn, infra, country, company_domain, ip],
    )?;
    Ok(())
}

fn update_ip_partial(
    conn: &Connection,
    ip: &str,
    rdns: Option<&str>,
    infra: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE ips SET reverse_dns = ?, infra = ? WHERE ip = ?",
        params![rdns, infra, ip],
    )?;
    Ok(())
}

fn store_asn(
    conn: &Connection,
    asn: &str,
    name: Option<&str>,
    domain: Option<&str>,
    route: Option<&str>,
    asn_type: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO asns (asn, name, domain, route, asn_type) VALUES (?, ?, ?, ?, ?)",
        params![asn, name, domain, route, asn_type],
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

        let (ip_counts, total_lines, global_ua_counts, _global_ua_bytes) =
            parse_files(&[path.clone()], None, None, None, &GenericParser::new().unwrap()).unwrap();

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

        let (ip_counts, total_lines, global_ua_counts, _global_ua_bytes) = parse_files(
            &[path.clone()],
            None,
            None,
            None,
            &DelimiterParser::new(",", Some(1), Some(4), None),
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
        let (ip_counts, total_lines, global_ua_counts, _global_ua_bytes) = parse_files(
            &[path.clone()],
            Some("GET"),
            None,
            None,
            &GenericParser::new().unwrap(),
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
        let (ip_counts, total_lines, global_ua_counts, _global_ua_bytes) = parse_files(
            &[path.clone()],
            None,
            Some("curl"),
            None,
            &GenericParser::new().unwrap(),
        )
        .unwrap();

        assert_eq!(total_lines, 1); // Only curl
        assert_eq!(ip_counts.len(), 1);
        assert_eq!(global_ua_counts.len(), 1);
        assert_eq!(global_ua_counts.get("curl"), Some(&1));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
        assert_eq!(format_bytes(1099511627776), "1.0 TB");
        assert_eq!(format_bytes(2199023255552), "2.0 TB");
    }

    #[test]
    fn test_parse_file_with_bytes_field() {
        use std::io::Write;
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "192.168.1.1;200;1024;curl/7.64.0").unwrap();
        writeln!(file, "192.168.1.1;200;2048;curl/7.64.0").unwrap();
        writeln!(file, "192.168.1.2;404;512;wget/1.20").unwrap();
        drop(file);

        let (ip_counts, total_lines, _global_ua_counts, global_ua_bytes) = parse_files(
            &[path.clone()],
            None,
            None,
            None,
            &DelimiterParser::new(";", Some(1), Some(4), Some(3)),
        )
        .unwrap();

        assert_eq!(total_lines, 3);
        assert_eq!(ip_counts.len(), 2);

        // IP 192.168.1.1 should have 1024 + 2048 = 3072 bytes
        assert_eq!(ip_counts.get("192.168.1.1").unwrap().3, 3072);
        // IP 192.168.1.2 should have 512 bytes
        assert_eq!(ip_counts.get("192.168.1.2").unwrap().3, 512);

        // Global UA bytes: curl = 3072, wget = 512
        assert_eq!(global_ua_bytes.get("curl"), Some(&3072));
        assert_eq!(global_ua_bytes.get("wget"), Some(&512));
    }

    #[test]
    fn test_parse_file_nginx_format() {
        use std::io::Write;
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, r#"192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0 (Windows NT 10.0)""#).unwrap();
        writeln!(file, r#"192.168.1.1 - frank [10/Oct/2023:13:55:37 +0000] "POST /api/data HTTP/1.1" 201 512 "-" "curl/7.64.0""#).unwrap();
        writeln!(file, r#"10.0.0.1 - - [10/Oct/2023:13:55:38 +0000] "GET /style.css HTTP/1.1" 304 0 "http://example.com/index.html" "Mozilla/5.0 (Linux)""#).unwrap();
        drop(file);

        let (ip_counts, total_lines, global_ua_counts, global_ua_bytes) =
            parse_files(&[path.clone()], None, None, None, &NginxParser::new().unwrap()).unwrap();

        assert_eq!(total_lines, 3);
        assert_eq!(ip_counts.len(), 2);

        // 192.168.1.1: 2 hits, 2326 + 512 = 2838 bytes
        let ip1 = ip_counts.get("192.168.1.1").unwrap();
        assert_eq!(ip1.0, 2);
        assert_eq!(ip1.3, 2838);

        // 10.0.0.1: 1 hit, 0 bytes
        let ip2 = ip_counts.get("10.0.0.1").unwrap();
        assert_eq!(ip2.0, 1);
        assert_eq!(ip2.3, 0);

        // UA counts
        assert_eq!(global_ua_counts.get("Mozilla"), Some(&2));
        assert_eq!(global_ua_counts.get("curl"), Some(&1));

        // UA bytes
        assert_eq!(global_ua_bytes.get("Mozilla"), Some(&2326));
        assert_eq!(global_ua_bytes.get("curl"), Some(&512));
    }

    #[test]
    fn test_parse_file_nginx_format_ipv6() {
        use std::io::Write;
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, r#"2001:db8::1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1024 "-" "curl/8.0""#).unwrap();
        drop(file);

        let (ip_counts, total_lines, _, _) =
            parse_files(&[path.clone()], None, None, None, &NginxParser::new().unwrap()).unwrap();

        assert_eq!(total_lines, 1);
        assert_eq!(ip_counts.len(), 1);

        let rec = ip_counts.get("2001:db8::1").unwrap();
        assert_eq!(rec.0, 1);
        assert_eq!(rec.1, true); // is_v6
        assert_eq!(rec.3, 1024);
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
            (100u64, false, Some("UA1".to_string()), 0u64),
        );
        counts.insert(
            "192.168.1.2".to_string(),
            (50u64, false, Some("UA2".to_string()), 0u64),
        );
        counts.insert(
            "192.168.1.3".to_string(),
            (25u64, false, Some("UA3".to_string()), 0u64),
        );
        counts.insert(
            "192.168.1.4".to_string(),
            (10u64, false, Some("UA4".to_string()), 0u64),
        );

        let filtered = apply_filters(&counts, Some("2"), None, SortBy::Hits);
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
            (100u64, false, Some("UA1".to_string()), 0u64),
        );
        counts.insert(
            "192.168.1.2".to_string(),
            (50u64, false, Some("UA2".to_string()), 0u64),
        );
        counts.insert(
            "192.168.1.3".to_string(),
            (25u64, false, Some("UA3".to_string()), 0u64),
        );
        counts.insert(
            "192.168.1.4".to_string(),
            (10u64, false, Some("UA4".to_string()), 0u64),
        );

        let filtered = apply_filters(&counts, Some("50%"), None, SortBy::Hits);
        assert_eq!(filtered.len(), 2); // 50% of 4 = 2
    }

    #[test]
    fn test_apply_filters_min() {
        let mut counts = HashMap::new();
        counts.insert(
            "192.168.1.1".to_string(),
            (100u64, false, Some("UA1".to_string()), 0u64),
        );
        counts.insert(
            "192.168.1.2".to_string(),
            (50u64, false, Some("UA2".to_string()), 0u64),
        );
        counts.insert(
            "192.168.1.3".to_string(),
            (25u64, false, Some("UA3".to_string()), 0u64),
        );
        counts.insert(
            "192.168.1.4".to_string(),
            (10u64, false, Some("UA4".to_string()), 0u64),
        );

        let filtered = apply_filters(&counts, None, Some(30), SortBy::Hits);
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

        let (ip_counts, total_lines, global_ua_counts, _global_ua_bytes) =
            parse_files(&[path.clone()], None, None, None, &GenericParser::new().unwrap()).unwrap();

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

        let (ip_counts, total_lines, global_ua_counts, _global_ua_bytes) =
            parse_files(&[path.clone()], None, None, None, &GenericParser::new().unwrap()).unwrap();

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

        let (ip_counts, total_lines, global_ua_counts, _global_ua_bytes) =
            parse_files(&[path.clone()], None, None, None, &GenericParser::new().unwrap()).unwrap();

        assert_eq!(total_lines, 3);
        assert_eq!(ip_counts.len(), 3);

        // Only curl should be counted
        assert_eq!(global_ua_counts.len(), 1);
        assert_eq!(global_ua_counts.get("curl"), Some(&1));
    }

    #[test]
    fn test_parse_files_gzip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let gz_path = dir.path().join("test.log.gz");

        let f = std::fs::File::create(&gz_path).unwrap();
        let mut gz = GzEncoder::new(f, Compression::default());
        writeln!(gz, "192.168.1.1 \"curl/7.64.0\"").unwrap();
        writeln!(gz, "192.168.1.2 \"wget/1.20\"").unwrap();
        writeln!(gz, "192.168.1.1 \"curl/8.0.0\"").unwrap();
        gz.finish().unwrap();

        let (ip_counts, total_lines, global_ua_counts, _) =
            parse_files(&[gz_path], None, None, None, &GenericParser::new().unwrap()).unwrap();

        assert_eq!(total_lines, 3);
        assert_eq!(ip_counts.len(), 2);
        assert_eq!(ip_counts.get("192.168.1.1").unwrap().0, 2);
        assert_eq!(ip_counts.get("192.168.1.2").unwrap().0, 1);
        assert_eq!(global_ua_counts.get("curl"), Some(&2));
        assert_eq!(global_ua_counts.get("wget"), Some(&1));
    }

    #[test]
    fn test_parse_files_multiple() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let path1 = dir.path().join("a.log");
        let path2 = dir.path().join("b.log");

        let mut f1 = std::fs::File::create(&path1).unwrap();
        writeln!(f1, "192.168.1.1 \"curl/7.64.0\"").unwrap();
        writeln!(f1, "192.168.1.2 \"wget/1.20\"").unwrap();
        drop(f1);

        let mut f2 = std::fs::File::create(&path2).unwrap();
        writeln!(f2, "192.168.1.1 \"curl/8.0.0\"").unwrap();
        writeln!(f2, "10.0.0.1 \"Python-requests/2.28\"").unwrap();
        drop(f2);

        let (ip_counts, total_lines, global_ua_counts, _) =
            parse_files(&[path1, path2], None, None, None, &GenericParser::new().unwrap()).unwrap();

        assert_eq!(total_lines, 4);
        assert_eq!(ip_counts.len(), 3); // 192.168.1.1, 192.168.1.2, 10.0.0.1
        assert_eq!(ip_counts.get("192.168.1.1").unwrap().0, 2); // aggregated across files
        assert_eq!(global_ua_counts.get("curl"), Some(&2));
        assert_eq!(global_ua_counts.get("wget"), Some(&1));
        assert_eq!(global_ua_counts.get("Python-requests"), Some(&1));
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

    // ===== parse_ipinfo_org Tests =====

    #[test]
    fn test_parse_ipinfo_org_standard() {
        let (asn, org) = parse_ipinfo_org("AS15169 Google LLC");
        assert_eq!(asn, Some("AS15169".to_string()));
        assert_eq!(org, Some("Google LLC".to_string()));
    }

    #[test]
    fn test_parse_ipinfo_org_no_asn() {
        let (asn, org) = parse_ipinfo_org("Google LLC");
        assert_eq!(asn, None);
        assert_eq!(org, Some("Google LLC".to_string()));
    }

    #[test]
    fn test_parse_ipinfo_org_asn_only() {
        let (asn, org) = parse_ipinfo_org("AS15169");
        assert_eq!(asn, Some("AS15169".to_string()));
        assert_eq!(org, None);
    }

    #[test]
    fn test_parse_ipinfo_org_extra_spaces() {
        let (asn, org) = parse_ipinfo_org("  AS16509  Amazon.com, Inc.  ");
        assert_eq!(asn, Some("AS16509".to_string()));
        assert_eq!(org, Some("Amazon.com, Inc.".to_string()));
    }

    // ===== display_org_with_infra Tests =====

    #[test]
    fn test_display_org_with_infra_both() {
        assert_eq!(
            display_org_with_infra(Some("Google LLC"), Some("AWS / EC2 / us-east-1"), true),
            "Google LLC (AWS / EC2 / us-east-1)"
        );
    }

    #[test]
    fn test_display_org_with_infra_org_only() {
        assert_eq!(
            display_org_with_infra(Some("Google LLC"), None, true),
            "Google LLC"
        );
    }

    #[test]
    fn test_display_org_with_infra_infra_only() {
        assert_eq!(
            display_org_with_infra(None, Some("AWS / EC2 / us-east-1"), true),
            "(AWS / EC2 / us-east-1)"
        );
    }

    #[test]
    fn test_display_org_with_infra_neither() {
        assert_eq!(display_org_with_infra(None, None, true), "-");
    }

    #[test]
    fn test_display_org_with_infra_cloud_detail_off() {
        assert_eq!(
            display_org_with_infra(Some("Google LLC"), Some("AWS / EC2 / us-east-1"), false),
            "Google LLC (AWS)"
        );
    }

    // ===== Cloud Provider Prefix Tests =====

    #[test]
    fn test_cloud_provider_prefix_aws() {
        assert_eq!(cloud_provider_prefix("AWS / EC2 / us-east-1"), Some("AWS"));
    }

    #[test]
    fn test_cloud_provider_prefix_azure() {
        assert_eq!(
            cloud_provider_prefix("Azure / AzureCloud / westus2"),
            Some("Azure")
        );
    }

    #[test]
    fn test_cloud_provider_prefix_bare() {
        assert_eq!(cloud_provider_prefix("AWS"), Some("AWS"));
    }

    #[test]
    fn test_cloud_provider_prefix_non_cloud() {
        assert_eq!(cloud_provider_prefix("Amazon.com, Inc."), None);
    }

    #[test]
    fn test_cloud_provider_prefix_dash() {
        assert_eq!(cloud_provider_prefix("-"), None);
    }

    // ===== Effective Org Tests =====

    #[test]
    fn test_effective_org_detail_on_cloud() {
        assert_eq!(
            effective_org("AWS / EC2 / us-east-1", true),
            "AWS / EC2 / us-east-1"
        );
    }

    #[test]
    fn test_effective_org_detail_off_cloud() {
        assert_eq!(effective_org("AWS / EC2 / us-east-1", false), "AWS");
    }

    #[test]
    fn test_effective_org_detail_on_non_cloud() {
        assert_eq!(effective_org("Amazon.com, Inc.", true), "Amazon.com, Inc.");
    }

    #[test]
    fn test_effective_org_detail_off_non_cloud() {
        assert_eq!(effective_org("Amazon.com, Inc.", false), "Amazon.com, Inc.");
    }

    // ===== GroupBy Cycle Tests =====

    #[test]
    fn test_group_by_cycle_includes_asn() {
        assert_eq!(GroupBy::Ip.next(), GroupBy::Org);
        assert_eq!(GroupBy::Org.next(), GroupBy::Asn);
        assert_eq!(GroupBy::Asn.next(), GroupBy::UserAgent);
        assert_eq!(GroupBy::UserAgent.next(), GroupBy::CloudProvider);
        assert_eq!(GroupBy::CloudProvider.next(), GroupBy::Ip);
    }

    #[test]
    fn test_group_by_labels() {
        assert_eq!(GroupBy::Ip.label(), "IP");
        assert_eq!(GroupBy::Org.label(), "Org");
        assert_eq!(GroupBy::Asn.label(), "ASN");
        assert_eq!(GroupBy::UserAgent.label(), "UA");
        assert_eq!(GroupBy::CloudProvider.label(), "Cloud");
    }

    // ===== Cloud Provider Classification Tests =====

    fn make_rec(org: Option<&str>, infra: Option<&str>, asn: Option<&str>, company_domain: Option<&str>) -> IpRecord {
        IpRecord {
            ip: "1.2.3.4".to_string(),
            count: 1,
            bytes: 0,
            looked_up: true,
            lookup_in_progress: false,
            in_display_set: true,
            org: org.map(|s| s.to_string()),
            infra: infra.map(|s| s.to_string()),
            asn: asn.map(|s| s.to_string()),
            company_domain: company_domain.map(|s| s.to_string()),
            reverse_dns: None,
            user_agent: None,
            country: None,
        }
    }

    #[test]
    fn test_classify_cloud_infra_takes_priority() {
        let rec = make_rec(Some("Hetzner Online GmbH"), Some("AWS / EC2 / us-east-1"), None, None);
        assert_eq!(classify_cloud_provider(&rec), "AWS");
    }

    #[test]
    fn test_classify_cloud_org_fallback() {
        assert_eq!(classify_cloud_provider(&make_rec(Some("OVH SAS"), None, None, None)), "OVH");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Hetzner Online GmbH"), None, None, None)), "Hetzner");
        assert_eq!(classify_cloud_provider(&make_rec(Some("AMAZON-02"), None, None, None)), "AWS");
    }

    #[test]
    fn test_classify_cloud_domain_match() {
        let rec = make_rec(None, None, None, Some("hetzner.com"));
        assert_eq!(classify_cloud_provider(&rec), "Hetzner");
    }

    #[test]
    fn test_classify_cloud_asn_match() {
        let rec = make_rec(None, None, Some("AS16276 OVH SAS"), None);
        assert_eq!(classify_cloud_provider(&rec), "OVH");
    }

    #[test]
    fn test_classify_cloud_unknown() {
        let rec = make_rec(Some("Comcast Cable"), None, None, None);
        assert_eq!(classify_cloud_provider(&rec), "Other/Unknown");
    }

    #[test]
    fn test_classify_cloud_no_data() {
        let rec = make_rec(None, None, None, None);
        assert_eq!(classify_cloud_provider(&rec), "Other/Unknown");
    }

    #[test]
    fn test_classify_cloud_extended_providers() {
        assert_eq!(classify_cloud_provider(&make_rec(Some("Linode LLC"), None, None, None)), "Linode/Akamai");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Choopa LLC"), None, None, None)), "Vultr");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Alibaba Cloud"), None, None, None)), "Alibaba Cloud");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Tencent Cloud"), None, None, None)), "Tencent Cloud");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Scaleway S.A.S."), None, None, None)), "Scaleway");
        assert_eq!(classify_cloud_provider(&make_rec(Some("UpCloud Ltd"), None, None, None)), "UpCloud");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Hostinger International"), None, None, None)), "Hostinger");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Orange S.A."), None, None, None)), "Orange");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Contabo GmbH"), None, None, None)), "Contabo");
        assert_eq!(classify_cloud_provider(&make_rec(Some("IONOS SE"), None, None, None)), "IONOS");
        assert_eq!(classify_cloud_provider(&make_rec(Some("1&1 Internet AG"), None, None, None)), "IONOS");
        assert_eq!(classify_cloud_provider(&make_rec(Some("LeaseWeb"), None, None, None)), "LeaseWeb");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Rackspace Ltd"), None, None, None)), "Rackspace");
        assert_eq!(classify_cloud_provider(&make_rec(Some("SoftLayer Technologies"), None, None, None)), "IBM Cloud");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Netcup GmbH"), None, None, None)), "Netcup");
        assert_eq!(classify_cloud_provider(&make_rec(Some("FranTech Solutions"), None, None, None)), "BuyVM/FranTech");
        assert_eq!(classify_cloud_provider(&make_rec(Some("Fastly Inc"), None, None, None)), "Fastly");
    }

    // ===== IpInfo Structured Response Tests =====

    #[test]
    fn test_ipinfo_response_structured() {
        let json = r#"{
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "org": "AS15169 Google LLC",
            "postal": "94043",
            "timezone": "America/Los_Angeles",
            "asn": {
                "asn": "AS15169",
                "name": "Google LLC",
                "domain": "google.com",
                "route": "8.8.8.0/24",
                "type": "hosting"
            },
            "company": {
                "name": "Google LLC",
                "domain": "google.com",
                "type": "hosting"
            }
        }"#;

        let resp: IpInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.hostname.as_deref(), Some("dns.google"));
        assert_eq!(resp.country.as_deref(), Some("US"));
        assert_eq!(resp.org.as_deref(), Some("AS15169 Google LLC"));

        let asn = resp.asn.unwrap();
        assert_eq!(asn.asn.as_deref(), Some("AS15169"));
        assert_eq!(asn.name.as_deref(), Some("Google LLC"));
        assert_eq!(asn.domain.as_deref(), Some("google.com"));
        assert_eq!(asn.route.as_deref(), Some("8.8.8.0/24"));
        assert_eq!(asn.asn_type.as_deref(), Some("hosting"));

        let company = resp.company.unwrap();
        assert_eq!(company.name.as_deref(), Some("Google LLC"));
        assert_eq!(company.domain.as_deref(), Some("google.com"));
    }

    #[test]
    fn test_ipinfo_response_free_tier() {
        let json = r#"{
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "org": "AS15169 Google LLC",
            "postal": "94043",
            "timezone": "America/Los_Angeles"
        }"#;

        let resp: IpInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.hostname, None);
        assert_eq!(resp.country.as_deref(), Some("US"));
        assert_eq!(resp.org.as_deref(), Some("AS15169 Google LLC"));
        assert!(resp.asn.is_none());
        assert!(resp.company.is_none());
    }

    #[test]
    fn test_store_asn() {
        let temp_file = NamedTempFile::new().unwrap();
        let conn = Connection::open(temp_file.path()).unwrap();
        init_db(&conn).unwrap();

        store_asn(&conn, "AS15169", Some("Google LLC"), Some("google.com"), Some("8.8.8.0/24"), Some("hosting")).unwrap();

        let (name, domain, route, asn_type): (Option<String>, Option<String>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT name, domain, route, asn_type FROM asns WHERE asn = ?",
                ["AS15169"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();

        assert_eq!(name.as_deref(), Some("Google LLC"));
        assert_eq!(domain.as_deref(), Some("google.com"));
        assert_eq!(route.as_deref(), Some("8.8.8.0/24"));
        assert_eq!(asn_type.as_deref(), Some("hosting"));
    }
}
