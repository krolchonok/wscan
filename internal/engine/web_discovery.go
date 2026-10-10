package engine

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type WebDiscoveryOptions struct {
	URL, Wordlist, Extensions, VirtualHost, Statuses, ExcludeSizes string
	RPS, Concurrency                                               int
	Timeout                                                        time.Duration
	Insecure, FilterWildcard                                       bool
}
type WebDiscoveryHit struct {
	URL         string
	Status      int
	Size        int64
	Location    string
	Title       string
	ContentType string
	Server      string
}
type WebDiscoveryProgress struct {
	Done, Total, Errors, Filtered int
	Hit                           *WebDiscoveryHit
}
type WebDiscoveryResult struct {
	Hits                          []WebDiscoveryHit
	Done, Total, Errors, Filtered int
	ErrorSample                   string
}

var webDiscoveryTitleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// extractPageTitle достаёт содержимое <title> из HTML-страницы: сворачивает
// пробелы/переводы строк, декодирует HTML-сущности и ограничивает длину,
// чтобы не раздувать отчёты бинарным или слишком длинным содержимым.
func extractPageTitle(contentType string, body []byte) string {
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "html") {
		return ""
	}
	match := webDiscoveryTitleRE.FindSubmatch(body)
	if match == nil {
		return ""
	}
	title := html.UnescapeString(string(match[1]))
	title = strings.Join(strings.Fields(title), " ")
	const maxTitleLen = 200
	if len(title) > maxTitleLen {
		title = strings.TrimSpace(title[:maxTitleLen]) + "…"
	}
	return title
}

var defaultWebWords = []string{"admin", "login", "api", "robots.txt", "sitemap.xml", "index", "index.php", "index.html", "dashboard", "config", "backup", "uploads", "images", "assets", "js", "css", "test", "dev", "staging", ".git/HEAD", ".env", "server-status", "phpinfo.php", "wp-admin", "wp-login.php", "wp-content", "actuator", "swagger", "swagger.json", "openapi.json", "health", "metrics", "debug", "old", "logs", "data", "files", "download", "includes", "vendor", "web.config", "README.md"}

func webDiscoveryNumbers(raw string) (map[int64]bool, error) {
	out := map[int64]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseInt(part, 10, 64)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("неверное число %q", part)
		}
		out[v] = true
	}
	return out, nil
}
func webDiscoveryPaths(o WebDiscoveryOptions) ([]string, error) {
	words := defaultWebWords
	if o.Wordlist != "" {
		f, err := os.Open(o.Wordlist)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		words = nil
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 64*1024)
		for scanner.Scan() {
			words = append(words, scanner.Text())
			if len(words) > 1000000 {
				return nil, fmt.Errorf("словарь превышает 1 000 000 строк")
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	suffixes := []string{""}
	for _, s := range strings.Split(o.Extensions, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		s = strings.TrimPrefix(s, ".")
		if strings.ContainsAny(s, "/\\?#") {
			return nil, fmt.Errorf("неверное расширение %q", s)
		}
		suffixes = append(suffixes, "."+s)
	}
	paths := []string{}
	seen := map[string]bool{}
	for _, word := range words {
		word = strings.TrimSpace(word)
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		word = strings.TrimLeft(word, "/")
		if strings.ContainsAny(word, "\\?#") {
			continue
		}
		valid := true
		for _, part := range strings.Split(word, "/") {
			if part == ".." || part == "." {
				valid = false
			}
		}
		if !valid || word == "" {
			continue
		}
		for _, ext := range suffixes {
			p := word + ext
			if !seen[p] {
				paths = append(paths, p)
				seen[p] = true
			}
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("словарь не содержит подходящих путей")
	}
	return paths, nil
}

type webDiscoveryResponse struct {
	hit       WebDiscoveryHit
	signature [32]byte
}

func DiscoverWeb(ctx context.Context, o WebDiscoveryOptions, progress func(WebDiscoveryProgress)) (WebDiscoveryResult, error) {
	result := WebDiscoveryResult{}
	base, err := url.Parse(o.URL)
	if err != nil || base.Hostname() == "" || (base.Scheme != "http" && base.Scheme != "https") || base.User != nil {
		return result, fmt.Errorf("укажи HTTP/HTTPS URL без учётных данных")
	}
	base.Fragment = ""
	base.RawQuery = ""
	base.Path = strings.TrimRight(base.Path, "/") + "/"
	base.RawPath = ""
	statuses, err := webDiscoveryNumbers(o.Statuses)
	if err != nil {
		return result, err
	}
	if len(statuses) == 0 {
		for _, s := range []int64{200, 204, 301, 302, 307, 308, 401, 403} {
			statuses[s] = true
		}
	}
	for s := range statuses {
		if s < 100 || s > 599 {
			return result, fmt.Errorf("HTTP-статус должен быть от 100 до 599")
		}
	}
	sizes, err := webDiscoveryNumbers(o.ExcludeSizes)
	if err != nil {
		return result, err
	}
	paths, err := webDiscoveryPaths(o)
	if err != nil {
		return result, err
	}
	result.Total = len(paths)
	workers := o.Concurrency
	if workers < 1 {
		workers = 4
	}
	if workers > 64 {
		workers = 64
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	rps := o.RPS
	if rps <= 0 {
		rps = 100
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, MaxIdleConns: workers, MaxIdleConnsPerHost: workers, TLSClientConfig: &tls.Config{InsecureSkipVerify: o.Insecure}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ticker := time.NewTicker(max(time.Nanosecond, time.Second/time.Duration(rps)))
	defer ticker.Stop()
	request := func(path string) (webDiscoveryResponse, error) {
		select {
		case <-ctx.Done():
			return webDiscoveryResponse{}, ctx.Err()
		case <-ticker.C:
		}
		target := *base
		target.Path = base.Path + path
		target.RawPath = ""
		req, err := http.NewRequestWithContext(ctx, "GET", target.String(), nil)
		if err != nil {
			return webDiscoveryResponse{}, err
		}
		req.Header.Set("User-Agent", "wscan-web-discovery")
		if o.VirtualHost != "" {
			req.Host = o.VirtualHost
		}
		response, err := client.Do(req)
		if err != nil {
			return webDiscoveryResponse{}, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
		if err != nil {
			return webDiscoveryResponse{}, err
		}
		size := int64(len(body))
		if response.ContentLength >= 0 {
			size = response.ContentLength
		}
		normalized := string(body) + "\nLocation: " + response.Header.Get("Location")
		for _, value := range []string{target.String(), target.RequestURI(), target.Path, path} {
			normalized = strings.ReplaceAll(normalized, value, "<path>")
		}
		contentType := response.Header.Get("Content-Type")
		hit := WebDiscoveryHit{
			URL:         target.String(),
			Status:      response.StatusCode,
			Size:        size,
			Location:    response.Header.Get("Location"),
			Title:       extractPageTitle(contentType, body),
			ContentType: contentType,
			Server:      response.Header.Get("Server"),
		}
		return webDiscoveryResponse{hit: hit, signature: sha256.Sum256([]byte(normalized))}, nil
	}
	if progress != nil {
		progress(WebDiscoveryProgress{Total: result.Total})
	}
	var wildcard *webDiscoveryResponse
	if o.FilterWildcard {
		random := make([]byte, 12)
		if _, err := rand.Read(random); err != nil {
			return result, err
		}
		probe := ".wscan-missing-" + hex.EncodeToString(random)
		first, err := request(probe + "-a")
		if err != nil {
			return result, fmt.Errorf("проверка несуществующего пути: %w", err)
		}
		second, err := request(probe + "-b")
		if err != nil {
			return result, fmt.Errorf("проверка несуществующего пути: %w", err)
		}
		if first.hit.Status == second.hit.Status && first.signature == second.signature {
			wildcard = &first
		}
	}
	var mu sync.Mutex
	var done atomic.Int64
	var wg sync.WaitGroup
	jobs := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				if ctx.Err() != nil {
					return
				}
				response, err := request(path)
				mu.Lock()
				event := WebDiscoveryProgress{Done: int(done.Add(1)), Total: result.Total}
				if err != nil {
					result.Errors++
					if result.ErrorSample == "" {
						result.ErrorSample = err.Error()
					}
				} else if !statuses[int64(response.hit.Status)] || sizes[response.hit.Size] || (wildcard != nil && response.hit.Status == wildcard.hit.Status && response.signature == wildcard.signature) {
					result.Filtered++
				} else {
					hit := response.hit
					result.Hits = append(result.Hits, hit)
					event.Hit = &hit
				}
				event.Errors = result.Errors
				event.Filtered = result.Filtered
				if progress != nil {
					progress(event)
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, path := range paths {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- path:
		}
	}
	close(jobs)
	wg.Wait()
	result.Done = int(done.Load())
	return result, ctx.Err()
}
