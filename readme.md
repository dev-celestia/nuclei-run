# nuclei-rs

High-performance, Nuclei-compatible vulnerability scanner written in Rust. Parses and executes ProjectDiscovery Nuclei YAML templates with async I/O, SIMD-accelerated pattern matching, and structured output.

## Features

- **Template Compatible** — Parses standard Nuclei v2/v3 HTTP templates including legacy `requests:` syntax, flexible author/reference fields, and raw HTTP payloads
- **5 Matcher Types** — Word (Aho-Corasick SIMD), Regex, Status Code, Binary (hex sequence), and DSL expression matchers
- **3 Extractor Types** — Regex with capture groups, Key-Value header lookup, and JSON dot-path extraction
- **Request Chaining** — Extract values from response N and inject them into request N+1
- **Rate Limiting** — Token-bucket rate limiter via `governor` with per-second request caps
- **Concurrent Workers** — Bounded async worker pool with configurable concurrency
- **3 Output Formats** — Colored terminal, JSON Lines (.jsonl), and OASIS SARIF v2.1.0
- **DSL Helpers** — Built-in `base64()`, `md5()`, `randstr`, `rand_int()`, `to_lower()`, `to_upper()`, `url_encode()`
- **Raw HTTP Support** — Sends raw multiline HTTP payloads for smuggling and CRLF injection templates
- **CI/CD Ready** — Non-zero exit code on critical/high findings, silent mode, stdin pipe support
- **UI Bridge** — Trait-based adapter for embedding into Tauri, egui, iced, or WebAssembly frontends
- **Tiny Binary** — 4.3 MB stripped release build with LTO

## Installation

### Build from source

```bash
git clone https://github.com/your-org/nuclei-rs.git
cd nuclei-rs
cargo build --release
```

The binary is at `target/release/nuclei-rs`.

### Requirements

- Rust 1.70+ (tested on 1.94)

## Quick Start

```bash
# Scan a single target
nuclei-rs -u https://target.com -t ./templates/

# Scan with severity filter and rate limit
nuclei-rs -u https://target.com -t ./cves/ -s high,critical -c 50 --rate-limit 150

# Scan from a target list with JSONL output
nuclei-rs -l targets.txt -t ./templates/ --jsonl -o results.jsonl

# Generate SARIF report for CI/CD
nuclei-rs -u https://staging.app -t ./templates/ --sarif -o results.sarif.json --silent

# Pipe targets from stdin
cat targets.txt | nuclei-rs -t ./templates/

# Custom headers and proxy
nuclei-rs -u https://target.com -t ./templates/ -H "Authorization: Bearer token" --proxy socks5://127.0.0.1:1080
```

## Usage

```
nuclei-rs [OPTIONS] --templates <TEMPLATES>

Options:
  -u, --url <URL>                      Target URL to scan
  -l, --list <LIST>                    File containing target URLs (one per line)
  -t, --templates <TEMPLATES>          Path to template file or directory
  -s, --severity <SEVERITY>            Filter by severity (comma-separated: info,low,medium,high,critical)
      --tags <TAGS>                    Filter by template tags (comma-separated)
      --id <ID>                        Filter by template IDs (comma-separated)
  -c, --concurrency <CONCURRENCY>      Number of concurrent workers [default: 25]
  -r, --rate-limit <RATE_LIMIT>        Maximum requests per second [default: 150]
      --timeout <TIMEOUT>              HTTP request timeout in seconds [default: 10]
      --retries <RETRIES>              Number of retries on failure [default: 1]
      --max-redirects <MAX_REDIRECTS>  Maximum redirects to follow [default: 10]
      --proxy <PROXY>                  HTTP/SOCKS5 proxy URL
  -H, --header <HEADER>                Custom headers (repeatable, format: "Key: Value")
  -o, --output <OUTPUT>                Output file path
      --jsonl                          Enable JSON Lines output
      --sarif                          Enable SARIF v2.1.0 output
      --silent                         Silent mode: suppress banner and progress
  -h, --help                           Print help
  -V, --version                        Print version
```

## Template Format

nuclei-rs supports standard Nuclei HTTP templates:

```yaml
id: example-cve-check
info:
  name: Example Vulnerability Check
  author: researcher
  severity: high
  description: Detects Example vulnerability
  tags: cve,example

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/debug"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "debug_mode"
          - "admin"
        condition: and
    extractors:
      - type: regex
        name: version
        part: body
        regex:
          - 'version":\s*"([^"]+)"'
        group: 1
```

### Supported Variables

| Variable | Description |
|---|---|
| `{{BaseURL}}` | Full target URL without trailing slash |
| `{{RootURL}}` | Scheme + hostname (no port or path) |
| `{{Hostname}}` | Hostname without port |
| `{{Host}}` | Hostname with port |
| `{{Port}}` | Port number |
| `{{Path}}` | URL path component |
| `{{Scheme}}` | http or https |
| `{{randstr}}` | Random 12-char alphanumeric string |
| `{{rand_int(min,max)}}` | Random integer in range |

### Supported Matchers

| Type | Description |
|---|---|
| `word` | Substring matching with SIMD acceleration (Aho-Corasick) |
| `regex` | Regular expression pattern matching |
| `status` | HTTP status code matching |
| `binary` | Hex-encoded byte sequence matching |
| `dsl` | Expression evaluation (e.g., `status_code == 200 && contains(body, "admin")`) |

### Supported Extractors

| Type | Description |
|---|---|
| `regex` | Regex extraction with capture group support |
| `kval` | Key-value header/cookie extraction |
| `json` | JSON dot-path extraction with array indexing |

## Architecture

```
src/
├── main.rs                  CLI entry point (clap)
├── lib.rs                   Library re-exports
├── config.rs                Runtime configuration
├── ui_bridge.rs             UI adapter trait (Tauri/egui/iced)
├── models/
│   ├── template.rs          Tolerant serde schema
│   └── result.rs            Finding and summary structs
├── parser/
│   └── yaml_loader.rs       Recursive directory loader with filtering
├── engine/
│   ├── variables.rs         URL placeholder resolution
│   ├── dsl.rs               Helper functions and DSL evaluator
│   ├── http_client.rs       Async HTTP client with raw request support
│   ├── matcher.rs           Multi-type pattern matcher
│   ├── extractor.rs         Value extraction engine
│   └── runner.rs            Worker pool orchestration with rate limiting
└── output/
    ├── stdout.rs            Colored terminal reporter
    ├── jsonl.rs             JSON Lines streaming writer
    └── sarif.rs             SARIF v2.1.0 report generator
```

## Output Examples

### Terminal (default)

```
[CVE-2023-XXXX] [http] [critical] https://target.com/api/debug ["root:x:0:0"]
[httpbin-status] [http] [info] https://httpbin.org/get
```

### JSON Lines (--jsonl)

```json
{"template_id":"CVE-2023-XXXX","template_name":"Example Vuln","severity":"critical","matched_url":"https://target.com/api/debug","matched_at":"2026-08-26T13:00:35Z","extracted_results":["root:x:0:0"],"protocol":"http"}
```

### SARIF v2.1.0 (--sarif)

Generates a standards-compliant SARIF report compatible with GitHub Code Scanning, Azure DevOps, and other SARIF consumers.

## CI/CD Integration

nuclei-rs exits with code 1 when critical or high severity findings are detected, making it suitable as a pipeline gate:

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    nuclei-rs -u ${{ env.STAGING_URL }} -t ./templates/ --sarif -o results.sarif.json --silent

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif.json
```

## UI Integration

The engine exposes a `UiScannerAdapter` trait for embedding into graphical frontends:

```rust
use nuclei_rs::ui_bridge::{UiScannerAdapter, UiScanConfig, ScannerEvent, NucleiUiEngine};
use tokio::sync::mpsc;

let engine = NucleiUiEngine::new();
let (tx, mut rx) = mpsc::channel::<ScannerEvent>(100);

engine.start_scan(config, tx).await?;

while let Some(event) = rx.recv().await {
    match event {
        ScannerEvent::FindingDiscovered(finding) => { /* update UI */ }
        ScannerEvent::ProgressUpdate { rps, .. } => { /* update progress bar */ }
        ScannerEvent::ScanCompleted { .. } => break,
        _ => {}
    }
}
```

Compatible with Tauri (event bus), egui/eframe (poll loop), and iced (subscription).

## Performance

| Metric | Value |
|---|---|
| Release binary size | 4.3 MB (stripped, LTO) |
| Word matching | SIMD-accelerated via Aho-Corasick |
| Async runtime | Tokio (multi-threaded) |
| TLS | rustls (no OpenSSL dependency) |
| Rate limiting | Token-bucket (governor) |
| Memory | Zero GC, bounded channels |

## License

MIT
