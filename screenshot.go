package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/chromedp/chromedp"
)

type Screenshotter struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
}

// newScreenshotter initializes a reusable headless Chrome allocator.
func newScreenshotter() (*Screenshotter, error) {
	chromePath, err := findChrome()
	if err != nil {
		return nil, fmt.Errorf("Chrome not found: %w (install Google Chrome or Chromium)", err)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("hide-scrollbars", false),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		// Bypass certificate errors for self-signed certs
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("ignore-ssl-errors", true),
		chromedp.Flag("ignore-certificate-errors-spki-list", true),
		// Set realistic window size
		chromedp.WindowSize(1920, 1080),
		// Use a realistic user agent
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// Test that Chrome actually starts
	testCtx, testCancel := chromedp.NewContext(allocCtx)
	defer testCancel()
	if err := chromedp.Run(testCtx); err != nil {
		allocCancel()
		return nil, fmt.Errorf("failed to start Chrome: %w", err)
	}

	return &Screenshotter{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
	}, nil
}

func (s *Screenshotter) Close() {
	s.allocCancel()
}

// Capture takes a screenshot of the given URL and saves it to outPath.
func (s *Screenshotter) Capture(targetURL, outPath string, timeout time.Duration) error {
	ctx, cancel := chromedp.NewContext(s.allocCtx)
	defer cancel()

	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	var buf []byte

	err := chromedp.Run(timeoutCtx,
		// Navigate and wait for network to settle
		chromedp.Navigate(targetURL),
		// Wait for either DOMContentLoaded or timeout
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Give the page a moment to render dynamic content
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}),
		// Capture full viewport screenshot
		chromedp.CaptureScreenshot(&buf),
	)
	if err != nil {
		// Fallback: try to capture whatever is loaded even on error
		if len(buf) > 0 {
			return os.WriteFile(outPath, buf, 0644)
		}
		return fmt.Errorf("capture failed: %w", err)
	}

	return os.WriteFile(outPath, buf, 0644)
}

// findChrome locates the Chrome/Chromium binary on the system.
func findChrome() (string, error) {
	candidates := chromeCandidates()
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	// Try PATH
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no Chrome installation found, checked: %v", candidates)
}

func chromeCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
		}
	case "linux":
		return []string{
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
			"/usr/local/bin/chromium",
		}
	case "windows":
		return []string{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			fmt.Sprintf(`%s\Google\Chrome\Application\chrome.exe`, os.Getenv("LOCALAPPDATA")),
		}
	default:
		return nil
	}
}
