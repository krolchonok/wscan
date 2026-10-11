package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wscan/internal/domain"
)

func cachedTestTemplate(id string) domain.Template {
	t := domain.Template{ID: id, Compatible: true, Risk: "read-only"}
	t.Info.Name = id
	t.Info.Severity = "info"
	t.HTTP = []domain.HTTPRequest{{Method: "GET", Path: domain.StringList{"{{BaseURL}}/"}, Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}}}}
	return t
}
func TestHTTPSharedResponsePreservesFindingsAndExpiresWithScan(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(15 * time.Millisecond)
		fmt.Fprint(w, "alpha beta")
	}))
	defer srv.Close()
	templates := []domain.Template{}
	for i := 0; i < 24; i++ {
		tmpl := cachedTestTemplate(fmt.Sprint(i))
		word := "alpha"
		if i%2 == 0 {
			word = "beta"
		}
		tmpl.HTTP[0].Matchers = append(tmpl.HTTP[0].Matchers, domain.Matcher{Type: "word", Part: "body", Words: []string{word}})
		tmpl.HTTP[0].MatchersCondition = "and"
		templates = append(templates, tmpl)
	}
	e := New(&fakeStore{}, Config{RPS: 1000, Concurrency: 8, TimeoutSeconds: 2})
	p := domain.Project{ID: 1, Targets: []string{srv.URL}, RPS: 1000, Concurrency: 8}
	for run := 1; run <= 2; run++ {
		result, err := e.Scan(context.Background(), p, templates)
		if err != nil || len(result.Errors) > 0 || len(result.Findings) != 24 || result.HTTPRequestsSaved != 23 {
			t.Fatalf("run %d: findings=%d saved=%d errors=%v err=%v", run, len(result.Findings), result.HTTPRequestsSaved, result.Errors, err)
		}
		if got := calls.Load(); got != int64(run) {
			t.Fatalf("run %d made %d cumulative requests", run, got)
		}
		ids := map[string]bool{}
		for _, f := range result.Findings {
			ids[f.TemplateID] = true
		}
		if len(ids) != 24 {
			t.Fatal("different template findings lost")
		}
	}
}
func TestHTTPCacheIsolationAndBypasses(t *testing.T) {
	cases := []string{"method", "authorization", "cookie", "cookie-reuse", "host", "headers", "size", "redirect-policy", "no-store", "set-cookie", "query", "timing", "raw", "flow", "payload", "response-error", "redirect-cookie", "private", "vary-star", "request-no-cache", "max-age-zero", "read-error", "truncated"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch name {
				case "private":
					w.Header().Set("Cache-Control", "private")
				case "vary-star":
					w.Header().Set("Vary", "*")
				case "max-age-zero":
					w.Header().Set("Cache-Control", "max-age=0")
				case "read-error":
					w.Header().Set("Content-Length", "100")
				case "no-store":
					w.Header().Set("Cache-Control", "public, no-store")
				case "set-cookie":
					w.Header().Set("Set-Cookie", "session=abc; Path=/")
				case "response-error":
					w.WriteHeader(500)
				case "redirect-cookie":
					if r.URL.Path == "/" {
						w.Header().Set("Set-Cookie", "session=abc; Path=/")
						http.Redirect(w, r, "/final", 302)
						return
					}
				}
				fmt.Fprint(w, "body")
			}))
			defer srv.Close()
			a, b := cachedTestTemplate("a"), cachedTestTemplate("b")
			switch name {
			case "request-no-cache":
				a.HTTP[0].Headers = map[string]string{"Cache-Control": "no-cache"}
				b.HTTP[0].Headers = a.HTTP[0].Headers
			case "method":
				b.HTTP[0].Method = "HEAD"
			case "authorization":
				a.HTTP[0].Headers = map[string]string{"Authorization": "Bearer a"}
				b.HTTP[0].Headers = map[string]string{"Authorization": "Bearer b"}
			case "cookie":
				a.HTTP[0].Headers = map[string]string{"Cookie": "session=a"}
				b.HTTP[0].Headers = map[string]string{"Cookie": "session=a"}
			case "cookie-reuse":
				a.HTTP[0].CookieReuse = true
				b.HTTP[0].CookieReuse = true
			case "host":
				a.HTTP[0].Headers = map[string]string{"Host": "a"}
				b.HTTP[0].Headers = map[string]string{"Host": "b"}
			case "headers":
				a.HTTP[0].Headers = map[string]string{"Accept-Language": "ru"}
				b.HTTP[0].Headers = map[string]string{"Accept-Language": "en"}
			case "truncated":
				a.HTTP[0].MaxSize = 2
				b.HTTP[0].MaxSize = 2
			case "size":
				a.HTTP[0].MaxSize = 2
			case "redirect-policy":
				b.HTTP[0].Redirects = true
			case "query":
				a.HTTP[0].Path = domain.StringList{"{{BaseURL}}/?action=check"}
				b.HTTP[0].Path = a.HTTP[0].Path
			case "timing":
				a.HTTP[0].Matchers = []domain.Matcher{{Type: "dsl", DSL: []string{"duration >= 0"}}}
				b.HTTP[0].Matchers = a.HTTP[0].Matchers
			case "raw":
				a.HTTP[0].Raw = domain.StringList{"GET / HTTP/1.1\nHost: {{Hostname}}\n\n"}
				a.HTTP[0].Path = nil
				b.HTTP[0].Raw = a.HTTP[0].Raw
				b.HTTP[0].Path = nil
			case "flow":
				a.Flow = "http(1)"
				b.Flow = a.Flow
			case "payload":
				a.HTTP[0].Payloads = domain.PayloadSet{"p": {Values: []string{"one"}}}
				b.HTTP[0].Payloads = a.HTTP[0].Payloads
			case "redirect-cookie":
				a.HTTP[0].Redirects = true
				b.HTTP[0].Redirects = true
			}
			e := New(&fakeStore{}, Config{RPS: 1000, Concurrency: 1, TimeoutSeconds: 2})
			result, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}, RPS: 1000, Concurrency: 1}, []domain.Template{a, b})
			expected := int64(2)
			if name == "redirect-cookie" {
				expected = 4
			}
			if err != nil || (name != "read-error" && len(result.Errors) > 0) || (name == "read-error" && len(result.Findings) != 0) || calls.Load() != expected || result.HTTPRequestsSaved != 0 {
				t.Fatalf("calls=%d want=%d saved=%d errors=%v err=%v", calls.Load(), expected, result.HTTPRequestsSaved, result.Errors, err)
			}
		})
	}
}
func TestHTTPCacheClearedAfterStateChangingRequest(t *testing.T) {
	var calls atomic.Int64
	var changed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == "POST" {
			changed.Store(true)
		}
		fmt.Fprint(w, changed.Load())
	}))
	defer srv.Close()
	a, b, post, c := cachedTestTemplate("a"), cachedTestTemplate("b"), cachedTestTemplate("post"), cachedTestTemplate("c")
	post.HTTP[0].Method = "POST"
	c.HTTP[0].Matchers = append(c.HTTP[0].Matchers, domain.Matcher{Type: "word", Part: "body", Words: []string{"true"}})
	c.HTTP[0].MatchersCondition = "and"
	e := New(&fakeStore{}, Config{RPS: 1000, Concurrency: 1, TimeoutSeconds: 2})
	result, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}, RPS: 1000, Concurrency: 1}, []domain.Template{a, b, post, c})
	if err != nil || len(result.Errors) > 0 || calls.Load() != 3 || result.HTTPRequestsSaved != 1 || len(result.Findings) != 4 {
		t.Fatalf("calls=%d saved=%d findings=%d errors=%v err=%v", calls.Load(), result.HTTPRequestsSaved, len(result.Findings), result.Errors, err)
	}
}
func TestHTTPCacheWaitCancellationAndInvalidationDuringFill(t *testing.T) {
	cache := newHTTPResponseCache()
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	load := func() (httpResponseData, error) {
		close(started)
		<-release
		return httpResponseData{status: 200, header: http.Header{}, body: []byte("old")}, nil
	}
	go func() { defer close(done); _, _ = cache.get(context.Background(), "host", "key", "leader", load) }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() { _, err := cache.get(ctx, "host", "key", "waiter", load); waiterDone <- err }()
	select {
	case err := <-waiterDone:
		t.Fatalf("waiter finished before leader: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-waiterDone:
		if err != context.Canceled {
			t.Fatalf("wait ignored cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter remained blocked after cancellation")
	}
	end := cache.beginChange("host")
	end()
	close(release)
	<-done
	fresh := func() (httpResponseData, error) {
		return httpResponseData{status: 200, header: http.Header{}, body: []byte("new")}, nil
	}
	out, err := cache.get(context.Background(), "host", "key", "next", fresh)
	if err != nil || string(out.body) != "new" {
		t.Fatalf("stale in-flight fill reused: %q %v", out.body, err)
	}
	out.body[0] = 'X'
	out.header.Set("Other", "changed")
	again, _ := cache.get(context.Background(), "host", "key", "other", fresh)
	if string(again.body) != "new" || again.header.Get("Other") != "" {
		t.Fatal("consumer mutated shared response")
	}
}
func TestHTTPCacheBodyBudgetAndSameTemplateFreshReads(t *testing.T) {
	cache := newHTTPResponseCache()
	var calls int
	load := func() (httpResponseData, error) {
		calls++
		return httpResponseData{status: 200, header: http.Header{}, body: []byte(strings.Repeat("x", 1<<20+1))}, nil
	}
	for _, owner := range []string{"a", "b"} {
		_, _ = cache.get(context.Background(), "host", "big", owner, load)
	}
	if calls != 2 || cache.bytes != 0 {
		t.Fatal("oversize response cached")
	}
	small := func() (httpResponseData, error) {
		calls++
		return httpResponseData{status: 200, header: http.Header{}, body: []byte("small")}, nil
	}
	_, _ = cache.get(context.Background(), "host", "same", "a", small)
	_, _ = cache.get(context.Background(), "host", "same", "a", small)
	if calls != 4 {
		t.Fatal("same template reused its own response")
	}
}

func TestHTTPCacheSharesHEADAndIdenticalAuthorization(t *testing.T) {
	for _, method := range []string{"GET", "HEAD"} {
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer same" {
					t.Error("authorization lost")
				}
				w.WriteHeader(200)
			}))
			defer srv.Close()
			a, b := cachedTestTemplate("a"), cachedTestTemplate("b")
			for _, tmpl := range []*domain.Template{&a, &b} {
				tmpl.HTTP[0].Method = method
				tmpl.HTTP[0].Headers = map[string]string{"Authorization": "Bearer same"}
			}
			e := New(&fakeStore{}, Config{RPS: 1000, Concurrency: 2, TimeoutSeconds: 2})
			result, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}, RPS: 1000, Concurrency: 2}, []domain.Template{a, b})
			if err != nil || calls.Load() != 1 || len(result.Findings) != 2 || result.HTTPRequestsSaved != 1 {
				t.Fatalf("calls=%d findings=%d saved=%d err=%v", calls.Load(), len(result.Findings), result.HTTPRequestsSaved, err)
			}
		})
	}
}
func TestHTTPCacheEntryLimitAndHostIsolation(t *testing.T) {
	cache := newHTTPResponseCache()
	load := func() (httpResponseData, error) {
		return httpResponseData{status: 200, header: http.Header{}, body: []byte("ok")}, nil
	}
	_, _ = cache.get(context.Background(), "other", "other-key", "a", load)
	for i := 0; i < httpCacheEntries+10; i++ {
		_, _ = cache.get(context.Background(), "host", fmt.Sprint(i), "a", load)
	}
	if len(cache.entries) != httpCacheEntries || cache.bytes > httpCacheBytes {
		t.Fatalf("cache exceeds bounds: entries=%d bytes=%d", len(cache.entries), cache.bytes)
	}
	end := cache.beginChange("host")
	end()
	if len(cache.entries) != 1 {
		t.Fatal("invalidation cleared another host or retained own entries")
	}
	_, _ = cache.get(context.Background(), "other", "other-key", "b", func() (httpResponseData, error) {
		t.Fatal("another host's response was invalidated")
		return httpResponseData{}, nil
	})
}
