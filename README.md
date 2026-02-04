# ip-report

A fast CLI tool to analyze IP addresses from log files, with optional reverse DNS and whois lookups.

## Features

- Parses log files efficiently with progress indicator
- Supports all IPv6 formats including compressed (`::`) notation
- Default mode: IP from first word/regex, UA from last quoted string (nginx format)
- Delimiter mode: fast field-based parsing for CSV/pipe-delimited logs
- Counts occurrences and sorts by frequency
- Shows percentage of total requests per IP
- Filter results with `--top N`, `--top N%`, or `--min N`
- Filter lines with `--filter` (whole line) or `--ua-filter` (user agent)
- Performs reverse DNS lookups and whois queries for organization info
- Caches results in SQLite to avoid redundant lookups
- Interactive TUI with scrollable results and live lookup updates
- Search/filter results in real-time (press s or /)
- Toggle columns (r/u/o) to reduce truncation
- Group by IP, Org, or User Agent (press g to cycle)
- Falls back to plain text output when piped

## Installation

```bash
cargo build --release
cp target/release/ip-report ~/.local/bin/  # or wherever you prefer
```

### Dependencies

Requires the `whois` command to be installed on your system:

- **macOS**: Built-in
- **Debian/Ubuntu**: `apt install whois`
- **Fedora/RHEL**: `dnf install whois`
- **Arch**: `pacman -S whois`

## Usage

```
ip-report [OPTIONS] <FILE>

Arguments:
  <FILE>  Input file to parse

Options:
      --top <TOP>              Show only top N IPs (e.g., "10" or "10%")
      --min <MIN>              Minimum occurrence count
      --db <DB>                SQLite database path [default: ip-report.db]
      --concurrency <N>        Max concurrent lookups [default: 20]
      --no-lookup              Skip DNS/whois lookups, only show counts
      --filter <PATTERN>       Filter lines by regex (matches whole line)
      --ua-filter <PATTERN>    Filter lines by user agent regex
      --delimiter <DELIM>      Field delimiter (enables fast field-based parsing)
      --ip-field <N>           1-indexed field number for IP (requires --delimiter)
      --ua-field <N>           1-indexed field number for user agent (requires --delimiter)
  -h, --help                   Print help
  -V, --version                Print version
```

## Examples

Show top 20 IPs from an nginx access log:
```bash
ip-report /var/log/nginx/access.log --top 20
```

Show IPs with at least 1000 hits, skip lookups:
```bash
ip-report access.log --min 1000 --no-lookup
```

Analyze top 5% of IPs with custom concurrency:
```bash
ip-report access.log --top 5% --concurrency 50
```

Filter for POST requests only:
```bash
ip-report access.log --top 50 --filter "POST"
```

Case-insensitive filter (prefix with `(?i)`):
```bash
ip-report access.log --filter "(?i)error|warning"
```

Filter for bot traffic by user agent:
```bash
ip-report access.log --top 20 --ua-filter "(?i)bot|crawl|spider"
```

Exclude Googlebot:
```bash
ip-report access.log --top 20 --ua-filter "^(?!.*Googlebot).*$"
```

Use a specific database file:
```bash
ip-report access.log --top 10 --db ~/.cache/ip-report.db
```

Pipe to file (non-interactive mode):
```bash
ip-report access.log --top 100 > report.txt
```

Parse pipe-delimited logs with explicit field positions:
```bash
ip-report cdn.log --delimiter '|' --ip-field 6 --ua-field 11
```

Parse CSV with auto-detected IP field:
```bash
ip-report data.csv --delimiter ','
```

## How it works

1. **Parsing**: Reads the file line by line with progress. In default mode, tries first word as IP (fast path), falls back to regex. In delimiter mode, splits by delimiter and uses specified field or auto-finds IP.

2. **Database**: For each filtered IP, checks SQLite cache. New IPs are inserted; IPs without lookup data trigger async lookups.

3. **Display**: In interactive mode, shows a scrollable TUI table that updates live as lookups complete. In non-interactive mode (piped), waits for all lookups then prints plain text.

## Keyboard shortcuts (TUI)

| Key | Action |
|-----|--------|
| `q` / `Esc` | Quit (or cancel search) |
| `s` / `/` | Start search |
| `Enter` | Confirm search |
| `g` | Cycle grouping: IP → Org → User Agent |
| `r` | Toggle reverse DNS column |
| `u` | Toggle user agent column |
| `o` | Toggle org column |
| `↑` / `k` | Scroll up |
| `↓` / `j` | Scroll down |
| `PgUp` | Scroll up 20 rows |
| `PgDn` | Scroll down 20 rows |
| `Home` | Go to top |
| `End` | Go to bottom |

## Notes

- `--top` and `--min` are mutually exclusive
- `--top 10%` means top 10% of unique IPs by count
- Percentage column shows each IP's share of total (filtered) requests
- Default mode: IP from first word or regex, UA from last quoted string (nginx format)
- For each IP, the most common user agent is stored and displayed
- Delimiter mode (`--delimiter`): faster parsing, no regex, auto-finds IP or uses `--ip-field`
- `--ip-field` and `--ua-field` are 1-indexed
- The database caches lookup results indefinitely; delete the `.db` file to force fresh lookups
- Lookups that fail silently show `-` in the output
- `--filter` and `--ua-filter` use Rust regex syntax; use `(?i)` prefix for case-insensitive

## License

MIT
