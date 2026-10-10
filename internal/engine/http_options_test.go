package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"wscan/internal/domain"
)

func runHTTPOptions(t *testing.T, target string, request domain.HTTPRequest) Result {
	t.Helper()
	engine := New(&fakeStore{}, Config{RPS: 1000, Concurrency: 1, TimeoutSeconds: 2})
	template := domain.Template{ID: "http-options", Compatible: true, HTTP: []domain.HTTPRequest{request}}
	result, err := engine.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{target}}, []domain.Template{template})
	if err != nil || len(result.Errors) != 0 {
		t.Fatalf("scan: %v errors=%v", err, result.Errors)
	}
	return result
}

func TestHTTPRedirectOptionsRespectSelectedService(t *testing.T) {
	var outside atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outside.Add(1); w.Write([]byte("outside")) }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/middle", 302)
		case "/middle":
			http.Redirect(w, r, "/finish", 302)
		case "/outside":
			http.Redirect(w, r, other.URL, 302)
		default:
			w.Write([]byte("finish"))
		}
	}))
	defer server.Close()
	for _, tc := range []struct {
		name, path               string
		redirects, hostRedirects bool
		maximum, status          int
	}{
		{"default", "/start", false, false, 0, 302},
		{"enabled", "/start", true, false, 2, 200},
		{"host-only", "/start", false, true, 2, 200},
		{"limit", "/start", true, false, 1, 302},
		{"outside-port", "/outside", true, false, 5, 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runHTTPOptions(t, server.URL, domain.HTTPRequest{Path: domain.StringList{"{{BaseURL}}" + tc.path}, Redirects: tc.redirects, HostRedirects: tc.hostRedirects, MaxRedirects: tc.maximum, Matchers: []domain.Matcher{{Type: "status", Status: []int{tc.status}}}})
			if len(result.Findings) != 1 {
				t.Fatalf("findings=%v", result.Findings)
			}
		})
	}
	if outside.Load() != 0 {
		t.Fatalf("redirect left selected service: %d", outside.Load())
	}
}

func TestHTTPCookieReuseAndDisable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "one", Path: "/"})
			return
		}
		cookie, err := r.Cookie("session")
		if err == nil && cookie.Value == "one" {
			w.Write([]byte("authenticated"))
		} else {
			w.WriteHeader(401)
		}
	}))
	defer server.Close()
	for _, tc := range []struct {
		name           string
		reuse, disable bool
		findings       int
	}{
		{"enabled", true, false, 1}, {"default", false, false, 0}, {"disabled", true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := runHTTPOptions(t, server.URL, domain.HTTPRequest{Path: domain.StringList{"{{BaseURL}}/set", "{{BaseURL}}/use"}, CookieReuse: tc.reuse, DisableCookie: tc.disable, Matchers: []domain.Matcher{{Type: "word", Words: []string{"authenticated"}}}})
			if len(result.Findings) != tc.findings {
				t.Fatalf("findings=%v", result.Findings)
			}
		})
	}
}

func TestHTTPCookiesDoNotLeakBetweenTemplates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "secret", Path: "/"})
			w.Write([]byte("set"))
			return
		}
		if _, err := r.Cookie("session"); err == nil {
			w.Write([]byte("leaked"))
		}
	}))
	defer server.Close()
	engine := New(&fakeStore{}, Config{RPS: 1000, Concurrency: 1, TimeoutSeconds: 2})
	templates := []domain.Template{
		{ID: "set", Compatible: true, HTTP: []domain.HTTPRequest{{Path: domain.StringList{"{{BaseURL}}/set"}, CookieReuse: true, Matchers: []domain.Matcher{{Type: "word", Words: []string{"set"}}}}}},
		{ID: "use", Compatible: true, HTTP: []domain.HTTPRequest{{Path: domain.StringList{"{{BaseURL}}/use"}, CookieReuse: true, Matchers: []domain.Matcher{{Type: "word", Words: []string{"leaked"}}}}}},
	}
	result, err := engine.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{server.URL}}, templates)
	if err != nil || len(result.Errors) != 0 || len(result.Findings) != 1 {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}

func TestHTTPStopAtFirstMatch(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	result := runHTTPOptions(t, server.URL, domain.HTTPRequest{Path: domain.StringList{"{{BaseURL}}/one", "{{BaseURL}}/two"}, StopAtFirstMatch: true, Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}}})
	if hits.Load() != 1 || len(result.Findings) != 1 {
		t.Fatalf("hits=%d findings=%v", hits.Load(), result.Findings)
	}
}

func TestHTTPResponseContextLivesUntilBodyIsRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(30 * time.Millisecond)
		w.Write([]byte("delayed-body-marker"))
	}))
	defer server.Close()
	result := runHTTPOptions(t, server.URL, domain.HTTPRequest{Path: domain.StringList{"{{BaseURL}}"}, Matchers: []domain.Matcher{{Type: "word", Words: []string{"delayed-body-marker"}}}})
	if len(result.Findings) != 1 {
		t.Fatalf("delayed body lost: %v", result.Findings)
	}
}

func TestHTTPMaxSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("prefix-tail-marker")) }))
	defer server.Close()
	result := runHTTPOptions(t, server.URL, domain.HTTPRequest{Path: domain.StringList{"{{BaseURL}}"}, MaxSize: 6, Matchers: []domain.Matcher{{Type: "word", Words: []string{"tail-marker"}}}})
	if len(result.Findings) != 0 {
		t.Fatalf("read beyond max-size: %v", result.Findings)
	}
}

func TestHTTPDisablePathAutomerge(t *testing.T) {
	var received atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Store(r.URL.Path); w.WriteHeader(200) }))
	defer server.Close()
	for _, tc := range []struct {
		disable bool
		path    string
	}{{true, "/exact"}, {false, "/base/exact"}} {
		result := runHTTPOptions(t, server.URL+"/base", domain.HTTPRequest{Raw: domain.StringList{"GET /exact HTTP/1.1\nHost: {{Hostname}}\n\n"}, DisablePathAutomerge: tc.disable, Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}}})
		if received.Load() != tc.path || len(result.Findings) != 1 {
			t.Fatalf("disable=%v path=%s findings=%v", tc.disable, received.Load(), result.Findings)
		}
	}
}
