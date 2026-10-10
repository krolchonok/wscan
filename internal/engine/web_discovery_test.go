package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func webTestWords(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestWebDiscoveryPathsFiltersAndRedirectScope(t *testing.T) {
	var outside atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outside.Add(1) }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "site.test" {
			t.Error("virtual host missing")
		}
		switch r.URL.Path {
		case "/app/admin":
			w.WriteHeader(403)
			w.Write([]byte("private"))
		case "/app/index.php":
			w.Write([]byte("index"))
		case "/app/redirect":
			http.Redirect(w, r, other.URL+"/outside", 302)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	result, err := DiscoverWeb(context.Background(), WebDiscoveryOptions{URL: server.URL + "/app/", VirtualHost: "site.test", Wordlist: webTestWords(t, "admin\nindex\nredirect\n../escape\n#comment\n"), Extensions: "php", RPS: 10000, Concurrency: 4, FilterWildcard: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 6 || result.Done != 6 || len(result.Hits) != 3 || outside.Load() != 0 {
		t.Fatalf("result=%+v outside=%d", result, outside.Load())
	}
	for _, h := range result.Hits {
		if !strings.HasPrefix(h.URL, server.URL+"/app/") {
			t.Fatal("escaped scope")
		}
	}
}
func TestWebDiscoveryWildcardEchoAndSizeFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real" {
			w.Write([]byte("real content"))
			return
		}
		w.Write([]byte("missing " + r.URL.Path))
	}))
	defer server.Close()
	o := WebDiscoveryOptions{URL: server.URL, Wordlist: webTestWords(t, "fake\nreal\n"), RPS: 10000, FilterWildcard: true}
	result, err := DiscoverWeb(context.Background(), o, nil)
	if err != nil || len(result.Hits) != 1 || !strings.HasSuffix(result.Hits[0].URL, "/real") {
		t.Fatalf("%+v %v", result, err)
	}
	o.ExcludeSizes = "12"
	result, err = DiscoverWeb(context.Background(), o, nil)
	if err != nil || len(result.Hits) != 0 {
		t.Fatalf("size filter: %+v %v", result, err)
	}
}
func TestWebDiscoveryRedirectWildcardKeepsDifferentLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		location := "/login"
		if r.URL.Path == "/admin" {
			location = "/admin/"
		}
		w.Header().Set("Location", location)
		w.WriteHeader(301)
	}))
	defer server.Close()
	result, err := DiscoverWeb(context.Background(), WebDiscoveryOptions{URL: server.URL, Wordlist: webTestWords(t, "admin\nmissing\n"), RPS: 10000, FilterWildcard: true}, nil)
	if err != nil || len(result.Hits) != 1 || result.Hits[0].Location != "/admin/" {
		t.Fatalf("%+v %v", result, err)
	}
}
func TestWebDiscoveryCancellationAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(40*time.Millisecond, cancel)
	started := time.Now()
	result, err := DiscoverWeb(ctx, WebDiscoveryOptions{URL: server.URL, Wordlist: webTestWords(t, "one\ntwo\nthree\n"), RPS: 10000, Timeout: time.Minute}, nil)
	if err != context.Canceled || time.Since(started) > time.Second {
		t.Fatalf("%+v %v", result, err)
	}
}
func TestWebDiscoveryExtractsPageMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/page":
			w.Header().Set("Server", "nginx/1.2.3")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte("<html>\n<head><TiTle>  Admin\n Panel &amp; Co  </TiTle></head><body></body></html>"))
		case "/app/data":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"title":"not a page title"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	result, err := DiscoverWeb(context.Background(), WebDiscoveryOptions{URL: server.URL + "/app/", Wordlist: webTestWords(t, "page\ndata\n"), RPS: 10000, Concurrency: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]WebDiscoveryHit{}
	for _, h := range result.Hits {
		byPath[strings.TrimPrefix(h.URL, server.URL+"/app/")] = h
	}
	page, ok := byPath["page"]
	if !ok || page.Title != "Admin Panel & Co" || page.Server != "nginx/1.2.3" || !strings.Contains(page.ContentType, "text/html") {
		t.Fatalf("unexpected page hit: %+v (ok=%v)", page, ok)
	}
	data, ok := byPath["data"]
	if !ok || data.Title != "" {
		t.Fatalf("expected no title for non-HTML content: %+v (ok=%v)", data, ok)
	}
}
func TestWebDiscoveryInputValidation(t *testing.T) {
	for _, o := range []WebDiscoveryOptions{{URL: "file:///etc/passwd"}, {URL: "http://user:secret@example.org"}, {URL: "http://example.org", Statuses: "abc"}, {URL: "http://example.org", Extensions: "php/../"}, {URL: "http://example.org", Wordlist: webTestWords(t, "../outside\n")}} {
		if _, err := DiscoverWeb(context.Background(), o, nil); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
}
