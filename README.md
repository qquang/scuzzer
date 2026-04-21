# Scuzzer

Web reconnaissance tool viết bằng Go — tự động phát hiện web service đang chạy trên các subdomain, nhận diện WAF/CDN, và chụp ảnh màn hình từng mục tiêu bằng headless Chrome.

---

## Luồng hoạt động

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
│       ├─▶ WAF Detection (12 loại)                  │
│       └─▶ Deduplicate by final URL                 │
└─────────────────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────┐
│  Phase 2: Screenshot                                │
│                                                     │
│  Headless Chrome (chromedp)                        │
│  → Navigate → Wait 2s render → CaptureScreenshot   │
│  → Save PNG vào <domain>/screenshots/              │
└─────────────────────────────────────────────────────┘
        │
        ▼
  Output: summary.txt, report.json, screenshots/
```

---

## Tính năng

### Port scanning thông minh
- **2-phase probe**: TCP connect trước → chỉ gửi HTTP request khi port thực sự mở → tránh lãng phí và timeout hàng loạt
- **Smart scheme ordering**: port 443/8443/4443 thử HTTPS trước, port 80/8080 thử HTTP trước → ít round-trip hơn
- **Protocol mismatch filter**: tự động loại bỏ response `400 plain HTTP request sent to HTTPS port` — không tính là false positive
- **Deduplication**: nếu nhiều port/scheme redirect về cùng một URL cuối → chỉ giữ một kết quả

### WAF / CDN Detection
Tự động nhận diện 12 loại WAF/CDN qua response headers và cookies:

| WAF / CDN | Dấu hiệu phát hiện |
|---|---|
| Cloudflare | `CF-Ray` header, `Server: cloudflare` |
| Akamai | `X-Check-Cacheable`, `AkamaiGHost` |
| AWS CloudFront | `X-Amz-Cf-Id`, `X-Cache: CloudFront` |
| AWS WAF | Body chứa `Request blocked` + `AWS` |
| Imperva | `X-Iinfo` header, cookie `visid_incap_*` |
| Sucuri | `X-Sucuri-ID`, `X-Sucuri-Cache` |
| Fastly | `X-Fastly-Request-ID` |
| F5 BIG-IP | Cookie prefix `TS*`, `Server: BigIP` |
| Barracuda | `X-Barracuda-Connect` |
| FortiWAF | `FORTIWAFSID` header |
| Reblaze | `X-Reblaze-Protection` |
| Azure Front Door | `X-Azure-Ref` |

### Screenshot
- Headless Chrome qua `chromedp` — render JavaScript đầy đủ
- Viewport 1920×1080, realistic User-Agent
- Bỏ qua TLS errors (self-signed cert, expired cert)
- Worker pool riêng, tách khỏi scan pool → scan không bị block bởi screenshot

### Output tự động theo domain
Output folder được đặt tên theo **root domain** tự suy luận từ danh sách input:
```
input: accts.mbs.com.vn, api.mbs.com.vn, web.mbs.com.vn
→ output folder: mbs.com.vn/
```

### Performance
- Worker pool với semaphore — không spawn goroutine không giới hạn
- HTTP connection pooling (`MaxIdleConnsPerHost: 10`, HTTP/2 support)
- Scan pool và screenshot pool độc lập — hai phase chạy tuần tự nhưng mỗi phase tối đa concurrency
- Browser instance dùng chung, chỉ mở tab mới cho mỗi screenshot

---

## Yêu cầu

- Go 1.22+
- Google Chrome hoặc Chromium (cho chức năng screenshot)

---

## Cài đặt

```bash
git clone https://github.com/qquang/scuzzer.git
cd scuzzer
go build -ldflags="-s -w" -o scuzzer .
```

---

## Sử dụng

```bash
./scuzzer [options]
```

### Options

| Flag | Default | Mô tả |
|---|---|---|
| `-i` | `subdomain` | File input chứa danh sách subdomain (một dòng một domain) |
| `-o` | auto | Thư mục output (mặc định tự suy luận từ root domain) |
| `-p` | `default` | Ports: `default`, `full`, hoặc danh sách tùy chỉnh `80,443,8080` |
| `-w` | `50` | Số lượng scan workers đồng thời |
| `-sw` | `5` | Số lượng screenshot workers đồng thời |
| `-dt` | `3s` | TCP dial timeout |
| `-ht` | `10s` | HTTP probe timeout |
| `-st` | `30s` | Screenshot timeout mỗi target |
| `-rate` | `0` | Delay giữa các request trên cùng một host (vd: `200ms`) |
| `-no-screenshot` | false | Bỏ qua bước screenshot, chỉ scan port |
| `-json` | false | Xuất thêm file `report.json` |
| `-v` | false | Verbose output (hiện cả các host không tìm thấy) |

### Ví dụ

```bash
# Scan cơ bản
./scuzzer -i subdomains.txt

# Scan nhanh, không screenshot
./scuzzer -i subdomains.txt -no-screenshot -w 100

# Full port list + JSON report
./scuzzer -i subdomains.txt -p full -w 30 -sw 3 -json

# Custom ports + rate limiting (tránh bị block)
./scuzzer -i subdomains.txt -p "80,443,8080,8443,9090" -rate 200ms -w 20

# Chỉ định thư mục output
./scuzzer -i subdomains.txt -o target_recon
```

### Format input

```
accts.example.com
api.example.com
https://web.example.com    # prefix http/https được tự động bỏ
# dòng comment bị bỏ qua
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
└── report.json       # full JSON (với -json flag)
```

### summary.txt
```
https://api.example.com   200   React App   Cloudflare
https://web.example.com   200   Login       
https://admin.example.com 403   Forbidden   Imperva
```

---

## Port lists

**`default`** (27 ports): Các port web phổ biến nhất
```
80, 443, 8080, 8443, 8000, 8888, 8008, 8081-8083, 8090, 9000, 9090, 9443, 3000, 3443, 4443, 5000, 5443, 7000, 7443, 8787, 9200, 9300, 10000, 10443
```

**`full`** (100+ ports): Toàn bộ port web thường gặp trong môi trường enterprise và cloud
