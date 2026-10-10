package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wscan/internal/domain"
)

func TestTargetVarsMatchNucleiHostConvention(t *testing.T) {
	vars := targetVars("http://10.0.0.10:80")
	if vars["Host"] != "10.0.0.10" {
		t.Fatalf("Host want bare hostname, got %q", vars["Host"])
	}
	if vars["Hostname"] != "10.0.0.10:80" {
		t.Fatalf("Hostname want host:port, got %q", vars["Hostname"])
	}
	if vars["Port"] != "80" {
		t.Fatalf("Port=%q", vars["Port"])
	}
}

func TestResolveURLPortOverride(t *testing.T) {
	// Same-host port rewrite used to be allowed; scoped service scans pin
	// the target port, so {{BaseURL}}:6080 is rejected.
	_, err := resolveURL("http://10.0.0.10:80", "{{BaseURL}}:6080/vnc.html")
	if err == nil || !strings.Contains(err.Error(), "leave target port") {
		t.Fatalf("expected leave-target-port error, got %v", err)
	}
	// Same port (explicit or default) stays fine.
	got, err := resolveURL("http://10.0.0.10:80", "{{BaseURL}}/vnc.html")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://10.0.0.10:80/vnc.html" {
		t.Fatalf("got %q", got)
	}
	// Selecting :8080 keeps web checks on 8080.
	got, err = resolveURL("http://10.0.0.10:8080", "{{BaseURL}}/admin")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://10.0.0.10:8080/admin" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveURLHostnameWithPortSameHost(t *testing.T) {
	got, err := resolveURL("http://10.0.0.10:80", "http://{{Hostname}}/version")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://10.0.0.10:80/version" {
		t.Fatalf("got %q", got)
	}
}

func TestOffPortHostAnnotationSkipped(t *testing.T) {
	// @Host rewriting to another port on the same host is out of scope for a
	// pinned service scan — request is skipped, no finding / no hard error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tmpl := domain.Template{ID: "off-port-host", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{{
		Raw: domain.StringList{"@Host: {{Host}}:19999\nGET / HTTP/1.1\nHost: example\n\n"},
		Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}},
	}}
	e := New(&fakeStore{}, Config{RPS: 50, Concurrency: 2, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("off-port @Host must not find, got %d", len(res.Findings))
	}
}

func TestParseRawAnnotations(t *testing.T) {
	pr, err := parseRaw("@timeout: 10s\n@once\n@Host: {{Host}}:9780\nGET /api HTTP/1.1\nHost: example\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if pr.method != "GET" || pr.path != "/api" {
		t.Fatalf("request line: %+v", pr)
	}
	if pr.timeout != 10*time.Second {
		t.Fatalf("timeout=%v", pr.timeout)
	}
	if !pr.once {
		t.Fatal("expected @once")
	}
	if pr.host != "{{Host}}:9780" {
		t.Fatalf("host=%q", pr.host)
	}
}

func TestPrepareRequestsOnceWithPayloads(t *testing.T) {
	req := domain.HTTPRequest{
		Raw: domain.StringList{
			"@once\nGET /once HTTP/1.1\nHost: h\n\n",
			"GET /{{p}} HTTP/1.1\nHost: h\n\n",
		},
		Attack: "batteringram",
		Payloads: map[string]domain.Payload{
			"p": {Values: []string{"a", "b", "c"}},
		},
	}
	out, errs := prepareRequests(req, nil, map[string]string{}, "", "")
	if len(errs) != 0 {
		t.Fatalf("errs=%v", errs)
	}
	var once, rest int
	for _, pr := range out {
		if pr.path == "/once" {
			once++
		} else {
			rest++
		}
	}
	if once != 1 {
		t.Fatalf("once count=%d want 1; out=%d", once, len(out))
	}
	if rest != 3 {
		t.Fatalf("payload paths=%d want 3", rest)
	}
}

func TestApplyHostOverrideSameHost(t *testing.T) {
	got, err := applyHostOverride("http://10.0.0.10:80/api", "10.0.0.10:9780")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://10.0.0.10:9780/api" {
		t.Fatalf("got %q", got)
	}
	if !sameTargetHost(got, "http://10.0.0.10:80") {
		t.Fatal("same host expected")
	}
	foreign, err := applyHostOverride("http://10.0.0.10:80/", "https://login.microsoftonline.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if sameTargetHost(foreign, "http://10.0.0.10:80") {
		t.Fatal("foreign host should not match")
	}
}

func TestTimeoutAnnotationSetsDuration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tmpl := domain.Template{ID: "timeout-duration", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{{
		Raw: domain.StringList{"@timeout: 2s\nGET / HTTP/1.1\nHost: {{Hostname}}\n\n"},
		Matchers: []domain.Matcher{{
			Type: "dsl",
			DSL:  []string{"duration>=0.15", "status_code==200"},
		}},
	}}
	e := New(&fakeStore{}, Config{RPS: 50, Concurrency: 2, TimeoutSeconds: 1})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings=%d errs=%v", len(res.Findings), res.Errors)
	}
}

func TestRewriteSSLAddress(t *testing.T) {
	if got := rewriteSSLAddress("10.0.0.10:80:80"); got != "10.0.0.10:80" {
		t.Fatalf("got %q", got)
	}
	if got := rewriteSSLAddress("10.0.0.10:443"); got != "10.0.0.10:443" {
		t.Fatalf("got %q", got)
	}
}

func TestInvalidHeaderNameSkipped(t *testing.T) {
	var sawBackslash bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.Header {
			if strings.Contains(k, `\`) {
				sawBackslash = true
			}
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	tmpl := domain.Template{ID: "bad-hdr", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{{
		Method: "GET",
		Path:   domain.StringList{"{{BaseURL}}/"},
		Headers: map[string]string{
			`\`:    "x",
			"X-Ok": "1",
		},
		Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}},
	}}
	e := New(&fakeStore{}, Config{RPS: 50, Concurrency: 2, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatal(err)
	}
	if sawBackslash {
		t.Fatal("invalid header should not reach server")
	}
	if len(res.Findings) != 1 || len(res.Errors) != 0 {
		t.Fatalf("findings=%d errs=%v", len(res.Findings), res.Errors)
	}
}
