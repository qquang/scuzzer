package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/sync/semaphore"
)

func main() {
	cfg := &Config{}

	flag.StringVar(&cfg.InputFile, "i", "subdomain", "Input file containing subdomains (one per line)")
	flag.StringVar(&cfg.OutputDir, "o", "", "Output directory (default: auto-detected main domain)")
	flag.IntVar(&cfg.ScanWorkers, "w", 50, "Number of concurrent scan workers")
	flag.IntVar(&cfg.ScreenWorkers, "sw", 5, "Number of concurrent screenshot workers")
	flag.DurationVar(&cfg.DialTimeout, "dt", 3*time.Second, "TCP dial timeout")
	flag.DurationVar(&cfg.HTTPTimeout, "ht", 10*time.Second, "HTTP probe timeout")
	flag.DurationVar(&cfg.ScreenTimeout, "st", 30*time.Second, "Screenshot timeout per target")
	flag.StringVar(&cfg.PortsFlag, "p", "default", "Ports: 'default', 'full', or comma-separated list e.g. 80,443,8080")
	flag.DurationVar(&cfg.RateDelay, "rate", 0, "Delay between requests per host (0 = no delay)")
	flag.BoolVar(&cfg.SkipScreenshot, "no-screenshot", false, "Skip screenshots, only scan ports")
	flag.BoolVar(&cfg.JSONOutput, "json", false, "Also save JSON report")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.Parse()

	cfg.Ports = parsePorts(cfg.PortsFlag)

	banner()

	// Read subdomains
	domains, err := readLines(cfg.InputFile)
	if err != nil {
		color.Red("[ERROR] Cannot read input file: %v", err)
		os.Exit(1)
	}
	domains = cleanDomains(domains)

	// Auto-detect output directory from main domain if not specified
	if cfg.OutputDir == "" {
		cfg.OutputDir = inferMainDomain(domains)
	}

	color.Cyan("[*] Loaded %d subdomains", len(domains))
	color.Cyan("[*] Output directory: %s", cfg.OutputDir)
	color.Cyan("[*] Scanning %d ports per subdomain", len(cfg.Ports))
	color.Cyan("[*] Scan workers: %d | Screenshot workers: %d", cfg.ScanWorkers, cfg.ScreenWorkers)
	fmt.Println()

	// Create output dir
	screenshotDir := filepath.Join(cfg.OutputDir, "screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		color.Red("[ERROR] Cannot create output directory: %v", err)
		os.Exit(1)
	}

	startTime := time.Now()

	// Phase 1: Scan all domains for open web ports
	color.Yellow("[*] Phase 1: Port scanning + HTTP probing...")
	targets := scanDomains(domains, cfg)

	color.Green("[+] Found %d live web targets in %s", len(targets), time.Since(startTime).Round(time.Second))
	fmt.Println()

	if len(targets) == 0 {
		color.Yellow("[!] No live targets found. Exiting.")
		return
	}

	// Phase 2: Screenshots
	if !cfg.SkipScreenshot {
		color.Yellow("[*] Phase 2: Taking screenshots...")
		screenSem := semaphore.NewWeighted(int64(cfg.ScreenWorkers))
		var wg sync.WaitGroup

		screenshotter, err := newScreenshotter()
		if err != nil {
			color.Red("[ERROR] Failed to initialize browser: %v", err)
			color.Yellow("[!] Skipping screenshots. Use -no-screenshot to suppress this.")
		} else {
			defer screenshotter.Close()

			for i := range targets {
				wg.Add(1)
				go func(t *WebTarget) {
					defer wg.Done()
					_ = screenSem.Acquire(nil_ctx(), 1)
					defer screenSem.Release(1)

					outPath := filepath.Join(screenshotDir, sanitizeFilename(t.Domain+"_"+fmt.Sprintf("%d", t.Port))+".png")
					if err := screenshotter.Capture(t.URL, outPath, cfg.ScreenTimeout); err != nil {
						if cfg.Verbose {
							color.Red("  [!] Screenshot failed %s: %v", t.URL, err)
						}
					} else {
						t.Screenshot = outPath
						color.Green("  [+] Screenshot: %s → %s", t.URL, filepath.Base(outPath))
					}
				}(targets[i])
			}
			wg.Wait()
		}
	}

	// Phase 3: Output report
	printReport(targets)

	if cfg.JSONOutput {
		reportPath := filepath.Join(cfg.OutputDir, "report.json")
		saveJSON(targets, reportPath)
		color.Cyan("[*] JSON report saved: %s", reportPath)
	}

	summaryPath := filepath.Join(cfg.OutputDir, "summary.txt")
	saveSummary(targets, summaryPath)
	color.Cyan("[*] Summary saved: %s", summaryPath)
	color.Green("[+] Done in %s", time.Since(startTime).Round(time.Second))
}

// inferMainDomain finds the common root domain shared by all subdomains.
// e.g. [accts.mbs.com.vn, api.mbs.com.vn] → "mbs.com.vn"
func inferMainDomain(domains []string) string {
	if len(domains) == 0 {
		return "output"
	}
	if len(domains) == 1 {
		return domains[0]
	}

	suffix := strings.Split(domains[0], ".")
	for _, d := range domains[1:] {
		parts := strings.Split(d, ".")
		suffix = commonSuffix(suffix, parts)
		if len(suffix) == 0 {
			return "output"
		}
	}

	// Must have at least 2 labels to be a meaningful domain
	if len(suffix) < 2 {
		return "output"
	}
	return strings.Join(suffix, ".")
}

func commonSuffix(a, b []string) []string {
	i, j := len(a)-1, len(b)-1
	var result []string
	for i >= 0 && j >= 0 && a[i] == b[j] {
		result = append([]string{a[i]}, result...)
		i--
		j--
	}
	return result
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func cleanDomains(domains []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, d := range domains {
		d = strings.TrimPrefix(d, "http://")
		d = strings.TrimPrefix(d, "https://")
		d = strings.TrimSuffix(d, "/")
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

func parsePorts(flag string) []int {
	switch flag {
	case "default":
		return defaultWebPorts
	case "full":
		return fullWebPorts
	default:
		return parseCustomPorts(flag)
	}
}

func printReport(targets []*WebTarget) {
	fmt.Println()
	color.Yellow("═══════════════════════════════════════════════════════════════")
	color.Yellow("  RESULTS: %d live web targets", len(targets))
	color.Yellow("═══════════════════════════════════════════════════════════════")

	for _, t := range targets {
		wafStr := ""
		if t.WAFType != "" {
			wafStr = color.YellowString(" [WAF: %s]", t.WAFType)
		}
		screenStr := ""
		if t.Screenshot != "" {
			screenStr = color.GreenString(" [screenshot]")
		}
		statusColor := color.GreenString("%d", t.StatusCode)
		if t.StatusCode >= 400 {
			statusColor = color.RedString("%d", t.StatusCode)
		} else if t.StatusCode >= 300 {
			statusColor = color.YellowString("%d", t.StatusCode)
		}

		fmt.Printf("  %s [%s] %s%s%s\n",
			color.CyanString(t.URL),
			statusColor,
			color.WhiteString(t.Title),
			wafStr,
			screenStr,
		)
	}
	fmt.Println()
}

func saveJSON(targets []*WebTarget, path string) {
	data, _ := json.MarshalIndent(targets, "", "  ")
	_ = os.WriteFile(path, data, 0644)
}

func saveSummary(targets []*WebTarget, path string) {
	var sb strings.Builder
	for _, t := range targets {
		sb.WriteString(fmt.Sprintf("%s\t%d\t%s\t%s\n", t.URL, t.StatusCode, t.Title, t.WAFType))
	}
	_ = os.WriteFile(path, []byte(sb.String()), 0644)
}
