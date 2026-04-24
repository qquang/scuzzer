package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"golang.org/x/sync/semaphore"
)

// Default common web ports ordered by frequency
var defaultWebPorts = []int{
	80, 443, 8080, 8443, 8000, 8888, 8008, 8081, 8082, 8083,
	8090, 9000, 9090, 9443, 3000, 3443, 4443, 5000, 5443,
	7000, 7443, 8787, 9200, 9300, 10000, 10443,
}

// Full web port list for thorough scanning
var fullWebPorts = []int{
	80, 443, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
	591, 593, 832, 981, 1010, 1311, 1099, 2082, 2083, 2086, 2087,
	2095, 2096, 2480, 3000, 3001, 3128, 3333, 3443, 4000, 4001,
	4002, 4100, 4443, 4444, 4445, 4567, 4711, 4712, 4848, 4993,
	4999, 5000, 5001, 5104, 5108, 5244, 5443, 5800, 5988, 5989,
	6000, 6543, 6789, 7000, 7001, 7002, 7396, 7474, 7443, 7674,
	8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
	8010, 8011, 8020, 8028, 8040, 8042, 8045, 8060, 8069, 8080,
	8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
	8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100,
	8180, 8181, 8243, 8280, 8281, 8333, 8383, 8443, 8444, 8445,
	8484, 8500, 8530, 8531, 8585, 8686, 8765, 8787, 8800, 8843,
	8888, 8880, 8887, 8889, 8983, 8989, 9000, 9001, 9002, 9003,
	9042, 9060, 9080, 9090, 9091, 9092, 9093, 9094, 9095, 9200,
	9294, 9295, 9300, 9418, 9443, 9444, 9800, 9981, 9988, 9999,
	10000, 10001, 10080, 10443, 11371, 12443, 16080, 17000, 18080,
	18081, 18091, 18092, 20000, 28017, 49152, 49153,
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
}

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

type WebTarget struct {
	URL        string        `json:"url"`
	Domain     string        `json:"domain"`
	Port       int           `json:"port"`
	StatusCode int           `json:"status_code"`
	Title      string        `json:"title"`
	Server     string        `json:"server"`
	IsHTTPS    bool          `json:"is_https"`
	WAFType    string        `json:"waf,omitempty"`
	FinalURL   string        `json:"final_url,omitempty"`
	Screenshot string        `json:"screenshot,omitempty"`
	RespTime   time.Duration `json:"response_time_ms"`
}

type Config struct {
	InputFile     string
	OutputDir     string
	ScanWorkers   int
	ScreenWorkers int
	DialTimeout   time.Duration
	HTTPTimeout   time.Duration
	ScreenTimeout time.Duration
	PortsFlag     string
	Ports         []int
	RateDelay     time.Duration
	SkipScreenshot bool
	JSONOutput    bool
	Verbose       bool
}

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func nil_ctx() context.Context {
	return context.Background()
}

// buildHTTPClient creates an optimized HTTP client for internet scanning.
// TLS verification is skipped intentionally (recon tool - handles expired/self-signed certs).
// Redirects are followed up to 10 times.
func buildHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			MinVersion:         tls.VersionTLS10,
		},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableCompression:    false,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			// Preserve browser-like headers on redirect
			req.Header.Set("User-Agent", via[0].Header.Get("User-Agent"))
			return nil
		},
	}
}

// tcpProbe checks if a TCP port is open with a fast dial.
func tcpProbe(host string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// httpProbe sends an HTTP request and returns target info if it's a web service.
func httpProbe(client *http.Client, rawURL string, domain string, port int, isHTTPS bool, verbose bool) *WebTarget {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}

	ua := randomUA()
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Cache-Control", "max-age=0")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		if verbose {
			color.Red("  [-] HTTP error %s: %v", rawURL, err)
		}
		return nil
	}
	defer resp.Body.Close()

	// Read up to 64KB to extract title
	buf := make([]byte, 65536)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	title := extractTitle(body)
	server := resp.Header.Get("Server")
	finalURL := resp.Request.URL.String()

	wafType := detectWAF(resp, body)

	target := &WebTarget{
		URL:        rawURL,
		Domain:     domain,
		Port:       port,
		StatusCode: resp.StatusCode,
		Title:      title,
		Server:     server,
		IsHTTPS:    isHTTPS,
		WAFType:    wafType,
		FinalURL:   finalURL,
		RespTime:   elapsed,
	}

	return target
}

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) > 1 {
		t := strings.TrimSpace(m[1])
		if len(t) > 100 {
			t = t[:97] + "..."
		}
		return t
	}
	return ""
}

// detectWAF identifies common WAF/CDN solutions from response headers and body.
func detectWAF(resp *http.Response, body string) string {
	headers := resp.Header

	// Cloudflare
	if headers.Get("CF-Ray") != "" || headers.Get("cf-ray") != "" {
		return "Cloudflare"
	}
	if headers.Get("Server") == "cloudflare" {
		return "Cloudflare"
	}

	// Akamai
	if headers.Get("X-Check-Cacheable") != "" || strings.Contains(headers.Get("Server"), "AkamaiGHost") {
		return "Akamai"
	}
	if headers.Get("X-Akamai-Transformed") != "" {
		return "Akamai"
	}

	// AWS WAF / CloudFront
	if headers.Get("X-Cache") != "" && strings.Contains(headers.Get("X-Cache"), "CloudFront") {
		return "AWS CloudFront"
	}
	if headers.Get("X-Amz-Cf-Id") != "" {
		return "AWS CloudFront"
	}
	if strings.Contains(body, "Request blocked") && strings.Contains(body, "AWS") {
		return "AWS WAF"
	}

	// Imperva / Incapsula
	if headers.Get("X-Iinfo") != "" {
		return "Imperva"
	}
	for _, cookie := range resp.Cookies() {
		if strings.HasPrefix(cookie.Name, "visid_incap_") || strings.HasPrefix(cookie.Name, "incap_ses_") {
			return "Imperva"
		}
	}

	// Sucuri
	if headers.Get("X-Sucuri-ID") != "" || headers.Get("X-Sucuri-Cache") != "" {
		return "Sucuri"
	}

	// Fastly
	if headers.Get("X-Fastly-Request-ID") != "" || strings.Contains(headers.Get("Via"), "Fastly") {
		return "Fastly"
	}

	// F5 BIG-IP
	for _, cookie := range resp.Cookies() {
		if strings.HasPrefix(cookie.Name, "TS") && len(cookie.Name) > 8 {
			return "F5 BIG-IP"
		}
	}
	if strings.Contains(headers.Get("Server"), "BigIP") || strings.Contains(headers.Get("Server"), "BIG-IP") {
		return "F5 BIG-IP"
	}

	// Barracuda
	if headers.Get("X-Barracuda-Connect") != "" {
		return "Barracuda"
	}

	// Fortinet
	if headers.Get("FORTIWAFSID") != "" {
		return "FortiWAF"
	}

	// Reblaze
	if headers.Get("X-Reblaze-Protection") != "" {
		return "Reblaze"
	}

	// ModSecurity (generic)
	if strings.Contains(body, "ModSecurity") || headers.Get("X-Mod-Security") != "" {
		return "ModSecurity"
	}

	// Azure Front Door
	if headers.Get("X-Azure-Ref") != "" {
		return "Azure Front Door"
	}

	// Generic 403 with no identifying server headers
	if resp.StatusCode == 403 && strings.Contains(strings.ToLower(body), "access denied") {
		srv := headers.Get("Server")
		if headers.Get("X-Powered-By") == "" && (srv == "" || srv == "-") {
			return "Unknown WAF"
		}
	}

	return ""
}

// scanDomains orchestrates concurrent domain scanning.
func scanDomains(domains []string, cfg *Config) []*WebTarget {
	sem := semaphore.NewWeighted(int64(cfg.ScanWorkers))
	client := buildHTTPClient(cfg.HTTPTimeout)

	var mu sync.Mutex
	var targets []*WebTarget
	var scanned atomic.Int64
	total := int64(len(domains))

	var wg sync.WaitGroup
	for _, domain := range domains {
		domain := domain
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sem.Acquire(context.Background(), 1)
			defer sem.Release(1)

			found := probeHost(client, domain, cfg)

			n := scanned.Add(1)
			if len(found) > 0 || cfg.Verbose {
				pct := int(n * 100 / total)
				for _, t := range found {
					wafStr := ""
					if t.WAFType != "" {
						wafStr = color.YellowString(" [%s]", t.WAFType)
					}
					color.Green("  [+] [%d%%] %s [%d] %s%s",
						pct, t.URL, t.StatusCode, t.Title, wafStr)
				}
			} else {
				n := scanned.Load()
				if n%50 == 0 {
					pct := int(n * 100 / total)
					color.White("  [.] [%d%%] scanned %d/%d hosts", pct, n, total)
				}
			}

			mu.Lock()
			targets = append(targets, found...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Sort by domain then port for consistent output
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Domain != targets[j].Domain {
			return targets[i].Domain < targets[j].Domain
		}
		return targets[i].Port < targets[j].Port
	})

	return targets
}

// probeHost scans all configured ports for a single domain.
func probeHost(client *http.Client, domain string, cfg *Config) []*WebTarget {
	var results []*WebTarget

	for _, port := range cfg.Ports {
		if cfg.RateDelay > 0 {
			time.Sleep(cfg.RateDelay)
		}

		// Fast TCP check first
		if !tcpProbe(domain, port, cfg.DialTimeout) {
			continue
		}

		// Determine scheme: try HTTPS first on common HTTPS ports
		schemes := schemeOrder(port)

		for _, scheme := range schemes {
			rawURL := fmt.Sprintf("%s://%s:%d", scheme, domain, port)

			// Normalize: skip default ports in URL for cleanliness
			if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
				rawURL = fmt.Sprintf("%s://%s", scheme, domain)
			}

			t := httpProbe(client, rawURL, domain, port, scheme == "https", cfg.Verbose)
			if t == nil {
				continue
			}

			// Protocol mismatch (e.g. HTTP sent to HTTPS port) → try other scheme
			if isProtocolMismatch(t) {
				continue
			}

			// Valid web service found on this port — record and move to next port.
			// No cross-port deduplication: port 8080 redirecting to :443 is still
			// an independent finding (the port is open and serving HTTP).
			results = append(results, t)
			break
		}
	}

	return results
}

// schemeOrder returns the order to try schemes for a given port.
// Known HTTPS ports get HTTPS first to avoid unnecessary HTTP→HTTPS redirect.
func schemeOrder(port int) []string {
	httpsFirst := map[int]bool{
		443: true, 8443: true, 4443: true, 5443: true, 3443: true,
		7443: true, 9443: true, 10443: true, 12443: true, 8445: true,
	}
	if httpsFirst[port] {
		return []string{"https", "http"}
	}
	return []string{"http", "https"}
}

// isProtocolMismatch returns true when HTTP was sent to an HTTPS port (or vice versa).
// Only matches the specific Nginx/server error for this condition — NOT generic 400s,
// which are legitimate app responses and must not be filtered out.
func isProtocolMismatch(t *WebTarget) bool {
	if t.StatusCode != 400 {
		return false
	}
	lowerTitle := strings.ToLower(t.Title)
	return strings.Contains(lowerTitle, "plain http") ||
		strings.Contains(lowerTitle, "https port")
}

func parseCustomPorts(s string) []int {
	var ports []int
	seen := make(map[int]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		var p int
		if _, err := fmt.Sscanf(part, "%d", &p); err == nil {
			if p > 0 && p < 65536 && !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return defaultWebPorts
	}
	return ports
}

func sanitizeFilename(s string) string {
	r := strings.NewReplacer(
		"/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_",
	)
	return r.Replace(s)
}
