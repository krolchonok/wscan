package engine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"wscan/internal/domain"
)

const httpCacheBytes = 64 << 20
const httpCacheEntries = 1024

type httpResponseData struct {
	status       int
	header       http.Header
	body         []byte
	elapsed      time.Duration
	cacheBlocked bool
	observedAt   time.Time
}

func (r httpResponseData) clone() httpResponseData {
	r.header = r.header.Clone()
	r.body = append([]byte(nil), r.body...)
	return r
}

type httpCacheEntry struct {
	response httpResponseData
	host     string
	owners   map[string]bool
	cost     int
}
type httpFlight struct{ done chan struct{} }

// One instance per ScanProgress. No response or credential is written to disk.
type httpResponseCache struct {
	mu      sync.Mutex
	entries map[string]*httpCacheEntry
	flights map[string]*httpFlight
	epochs  map[string]uint64
	active  map[string]int
	bytes   int
	hits    int64
}

func newHTTPResponseCache() *httpResponseCache {
	return &httpResponseCache{entries: map[string]*httpCacheEntry{}, flights: map[string]*httpFlight{}, epochs: map[string]uint64{}, active: map[string]int{}}
}
func cacheHost(target string) string {
	u, err := url.Parse(normalizeTarget(target))
	if err != nil {
		return target
	}
	return strings.ToLower(u.Hostname())
}

// Also guards in-flight fills: a response started before a stateful check must
// never populate the cache after that check. Other hosts retain their entries.
func (c *httpResponseCache) beginChange(host string) func() {
	c.mu.Lock()
	c.active[host]++
	c.invalidateLocked(host)
	c.mu.Unlock()
	return func() { c.mu.Lock(); c.active[host]--; c.invalidateLocked(host); c.mu.Unlock() }
}
func (c *httpResponseCache) invalidateLocked(host string) {
	c.epochs[host]++
	for key, e := range c.entries {
		if e.host == host {
			c.bytes -= e.cost
			delete(c.entries, key)
		}
	}
}
func (c *httpResponseCache) get(ctx context.Context, host, key, owner string, load func() (httpResponseData, error)) (httpResponseData, error) {
	for {
		if err := ctx.Err(); err != nil {
			return httpResponseData{}, err
		}
		c.mu.Lock()
		if c.active[host] > 0 {
			c.mu.Unlock()
			return load()
		}
		epoch := c.epochs[host]
		if e := c.entries[key]; e != nil {
			// Repeated reads by the same template may be a control or consistency
			// check. Only different template executions may share this snapshot.
			cost := len(owner) + 64
			if e.owners[owner] || c.bytes+cost > httpCacheBytes {
				c.mu.Unlock()
				return load()
			}
			e.owners[owner] = true
			e.cost += cost
			c.bytes += cost
			c.hits++
			out := e.response.clone()
			c.mu.Unlock()
			return out, nil
		}
		flightKey := fmt.Sprintf("%s:%d", key, epoch)
		if f := c.flights[flightKey]; f != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return httpResponseData{}, ctx.Err()
			case <-f.done:
				continue
			}
		}
		f := &httpFlight{done: make(chan struct{})}
		c.flights[flightKey] = f
		c.mu.Unlock()
		out, err := load()
		c.mu.Lock()
		if err == nil && ctx.Err() == nil && c.epochs[host] == epoch && c.active[host] == 0 && cacheableHTTPResponse(out) {
			cost := len(out.body) + len(owner) + len(key) + 1024
			for k, v := range out.header {
				cost += len(k)
				for _, s := range v {
					cost += len(s)
				}
			}
			if len(c.entries) < httpCacheEntries && c.bytes+cost <= httpCacheBytes {
				c.entries[key] = &httpCacheEntry{response: out.clone(), host: host, owners: map[string]bool{owner: true}, cost: cost}
				c.bytes += cost
			}
		}
		delete(c.flights, flightKey)
		close(f.done)
		c.mu.Unlock()
		return out, err
	}
}
func cacheControlBypass(h http.Header) bool {
	for _, v := range h.Values("Cache-Control") {
		for _, directive := range strings.Split(strings.ToLower(v), ",") {
			parts := strings.SplitN(directive, "=", 2)
			name := strings.TrimSpace(parts[0])
			if (name == "max-age" || name == "s-maxage") && len(parts) == 2 && strings.Trim(strings.TrimSpace(parts[1]), "\"") == "0" {
				return true
			}
			if name == "no-store" || name == "no-cache" || name == "private" {
				return true
			}
		}
	}
	return false
}
func cacheableHTTPResponse(r httpResponseData) bool {
	if r.cacheBlocked || r.status < 200 || r.status >= 300 || len(r.body) > 1<<20 || len(r.header.Values("Set-Cookie")) > 0 || cacheControlBypass(r.header) {
		return false
	}
	for _, v := range r.header.Values("Vary") {
		for _, name := range strings.Split(v, ",") {
			if strings.TrimSpace(name) == "*" {
				return false
			}
		}
	}
	return true
}
func cacheableTemplate(t domain.Template) bool {
	if t.IsExploit || t.Flow != "" || len(t.HTTP) != 1 || len(t.Code)+len(t.JavaScript)+len(t.TCP)+len(t.Network)+len(t.DNS)+len(t.SSL)+len(t.Workflows) > 0 {
		return false
	}
	r := t.HTTP[0]
	if len(r.Raw) > 0 || len(r.Payloads) > 0 || r.Body != "" || r.CookieReuse || r.ID != "" {
		return false
	}
	for _, tag := range strings.Split(strings.ToLower(t.Info.Tags), ",") {
		switch strings.TrimSpace(tag) {
		case "exploit", "dos", "brute", "bruteforce", "fuzz", "fuzzing", "race-condition", "rce", "sqli", "ssrf", "ssti", "xxe", "upload", "auth-bypass", "csrf", "xss", "auth", "credentials", "default-login", "default-logins", "credential-stuffing":
			return false
		}
	}
	// Timing and OAST assertions must observe their own network exchange.
	b, _ := json.Marshal(r)
	for _, term := range []string{"duration", "interactsh", "randstr", "rand_int", "rand_base"} {
		if strings.Contains(strings.ToLower(string(b)), term) {
			return false
		}
	}
	return true
}
func httpResponseCacheKey(req *http.Request, r domain.HTTPRequest, timeout time.Duration, limit int64) (string, bool) {
	if (req.Method != "GET" && req.Method != "HEAD") || req.ContentLength != 0 || req.URL.RawQuery != "" || req.Header.Get("Cookie") != "" || cacheControlBypass(req.Header) || req.Header.Get("Pragma") != "" {
		return "", false
	}
	data, _ := json.Marshal(struct {
		Method, URL, Host                              string
		Headers                                        http.Header
		Redirects, HostRedirects, DisablePathAutomerge bool
		MaxRedirects                                   int
		Timeout                                        time.Duration
		Limit                                          int64
	}{req.Method, req.URL.String(), req.Host, req.Header, r.Redirects, r.HostRedirects, r.DisablePathAutomerge, r.MaxRedirects, timeout, limit})
	return fmt.Sprintf("%x", sha256.Sum256(data)), true
}

func fetchHTTPResponse(ctx context.Context, client *http.Client, ec execContext, timeout time.Duration, limit int64, build func(context.Context) (*http.Request, error)) (httpResponseData, error) {
	for attempt := 0; attempt <= ec.retries; attempt++ {
		if ec.rateTick != nil {
			select {
			case <-ctx.Done():
				return httpResponseData{}, ctx.Err()
			case <-ec.rateTick:
			}
		}
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return httpResponseData{}, ctx.Err()
			case <-time.After(time.Duration(attempt) * 150 * time.Millisecond):
			}
		}
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		req, err := build(requestCtx)
		if err != nil {
			cancel()
			return httpResponseData{}, err
		}
		blocked := false
		localClient := *client
		redirect := client.CheckRedirect
		localClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
			if next.Response != nil && (len(next.Response.Header.Values("Set-Cookie")) > 0 || cacheControlBypass(next.Response.Header)) {
				blocked = true
			}
			if redirect != nil {
				return redirect(next, via)
			}
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		}
		started := time.Now()
		resp, err := localClient.Do(req)
		elapsed := time.Since(started)
		if err != nil {
			cancel()
			if attempt == ec.retries {
				return httpResponseData{}, err
			}
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
		_ = resp.Body.Close()
		cancel()
		if err != nil {
			return httpResponseData{}, fmt.Errorf("read HTTP response: %w", err)
		}
		if req.Method != "HEAD" && (resp.ContentLength > limit || (resp.ContentLength < 0 && int64(len(body)) >= limit)) {
			blocked = true
		}
		return httpResponseData{status: resp.StatusCode, header: resp.Header.Clone(), body: body, elapsed: elapsed, cacheBlocked: blocked, observedAt: started.UTC()}, nil
	}
	return httpResponseData{}, fmt.Errorf("HTTP retry budget exhausted")
}
