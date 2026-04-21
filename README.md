# Scuzzer

Web reconnaissance tool — automatically discovers web services running on subdomains, identifies WAF/CDN protections, and captures screenshots of each target using headless Chrome.

---

## How It Works

```
Input (subdomain list)
        │
        ▼
┌─────────────────────────────────────────────────────┐
│  Phase 1: Port Discovery                            │
│                                                     │
│  TCP Connect (3s timeout) ──✗──▶ skip               │
│       │ ✓                                           │
│       ▼                                             │
│  HTTP Probe (realistic browser headers)             │
│       │                                             │
│       ├─▶ Protocol mismatch? ──▶ try other scheme  │
│       ├─▶ WAF Detection (12 types)                 │
│       └─▶ Deduplicate by final URL                 │
└─────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────┐
│  Phase 2: Screenshot                                │
│                                                     │
│  Headless Chrome (chromedp)                        │
│  → Navigate → Wait 2s render → CaptureScreenshot   │
│  → Save PNG to <domain>/screenshots/               │
└─────────────────────────────────────────────────────┘
        │
        ▼
  Output: summary.txt, report.json, screenshots/
```

---

## Features

### Smart Port Scanning
- **2-phase probe**: TCP connect first → only sends HTTP request when port is actually open, avoiding wasted requests and mass timeouts
- **Smart scheme ordering**: ports 443/8443/4443 try HTTPS first, ports 80/8080 try HTTP first — fewer round-trips
- **Protocol mismatch filter**: automatically drops `400 plain HTTP request sent to HTTPS port` responses — not counted as findings
- **Deduplication**: if multiple ports/schemes redirect to the same final URL, only one result is kept

### WAF / CDN Detection
Automatically identifies 12 WAF/CDN types via response headers and cookies:

| WAF / CDN | Detection Signal |
|---|---|
| Cloudflare | `CF-Ray` header, `Server: cloudflare` |
| Akamai | `X-Check-Cacheable`, `AkamaiGHost` |
| AWS CloudFront | `X-Amz-Cf-Id`, `X-Cache: CloudFront` |
| AWS WAF | Body contains `Request blocked` + `AWS` |
| Imperva | `X-Iinfo` header, cookie `visid_incap_*` |
| Sucuri | `X-Sucuri-ID`, `X-Sucuri-Cache` |
| Fastly | `X-Fastly-Request-ID` |
| F5 BIG-IP | Cookie prefix `TS*`, `Server: BigIP` |
| Barracuda | `X-Barracuda-Connect` |
| FortiWAF | `FORTIWAFSID` header |
| Reblaze | `X-Reblaze-Protection` |
| Azure Front Door | `X-Azure-Ref` |

### Screenshot
- Headless Chrome via `chromedp` — full JavaScript rendering
- 1920×1080 viewport, realistic User-Agent
- Ignores TLS errors (self-signed and expired certificates)
- Separate worker pool from scan pool — screenshots never block port scanning

### Auto-named Output Directory
Output folder is named after the **root domain** inferred from the input list:
```
input: accts.example.com, api.example.com, web.example.com
→ output folder: example.com/
```

### Performance
- Worker pools with semaphore — no unbounded goroutine spawning
- HTTP connection pooling (`MaxIdleConnsPerHost: 10`, HTTP/2 support)
- Scan and screenshot pools are independent — each phase runs at full concurrency
- Single shared browser instance — only new tabs are opened per screenshot

---

## Requirements

- Go 1.22+
- Google Chrome or Chromium (for screenshot functionality)

---

## Installation

```bash
git clone https://github.com/qquang/scuzzer.git
cd scuzzer
go build -ldflags="-s -w" -o scuzzer .
```

---

## Usage

```bash
./scuzzer [options]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-i` | `subdomain` | Input file with subdomain list (one per line) |
| `-o` | auto | Output directory (defaults to inferred root domain) |
| `-p` | `default` | Ports: `default`, `full`, or custom list e.g. `80,443,8080` |
| `-w` | `50` | Number of concurrent scan workers |
| `-sw` | `5` | Number of concurrent screenshot workers |
| `-dt` | `3s` | TCP dial timeout |
| `-ht` | `10s` | HTTP probe timeout |
| `-st` | `30s` | Screenshot timeout per target |
| `-rate` | `0` | Delay between requests per host (e.g. `200ms`) |
| `-no-screenshot` | false | Skip screenshots, port scan only |
| `-json` | false | Also output `report.json` |
| `-v` | false | Verbose output |

### Examples

```bash
# Basic scan
./scuzzer -i subdomains.txt

# Fast scan, no screenshots
./scuzzer -i subdomains.txt -no-screenshot -w 100

# Full port list + JSON report
./scuzzer -i subdomains.txt -p full -w 30 -sw 3 -json

# Custom ports + rate limiting
./scuzzer -i subdomains.txt -p "80,443,8080,8443,9090" -rate 200ms -w 20

# Specify output directory
./scuzzer -i subdomains.txt -o target_recon
```

### Input Format

```
accts.example.com
api.example.com
https://web.example.com    # http/https prefix is stripped automatically
# lines starting with # are ignored
```

---

## Output

```
<domain>/
├── screenshots/
│   ├── api.example.com_443.png
│   ├── web.example.com_80.png
│   └── ...
├── summary.txt       # tab-separated: url, status, title, waf
└── report.json       # full JSON (with -json flag)
```

### summary.txt
```
https://api.example.com    200   React App   Cloudflare
https://web.example.com    200   Login
https://admin.example.com  403   Forbidden   Imperva
```

---

## Port Lists

**`default`** (27 ports): Most common web ports
```
80, 443, 8080, 8443, 8000, 8888, 8008, 8081-8083, 8090, 9000, 9090, 9443, 3000, 3443, 4443, 5000, 5443, 7000, 7443, 8787, 9200, 9300, 10000, 10443
```

**`full`** (100+ ports): Extended list covering enterprise and cloud environments
