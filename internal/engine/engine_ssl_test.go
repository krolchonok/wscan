package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wscan/internal/domain"
)

func TestEngineXPathMatcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><input name="authenticity_token" value="tok123"/></body></html>`))
	}))
	defer srv.Close()

	tmpl := domain.Template{ID: "xpath-test", Compatible: true, Risk: "read-only"}
	tmpl.Info.Name = "xpath"
	tmpl.HTTP = []domain.HTTPRequest{{
		Method: "GET",
		Path:   domain.StringList{"{{BaseURL}}/"},
		Matchers: []domain.Matcher{{
			Type:  "xpath",
			Part:  "body",
			XPath: []string{`//input[@name="authenticity_token"]`},
		}},
		Extractors: []domain.Extractor{{
			Type:      "xpath",
			Attribute: "value",
			XPath:     []string{`//input[@name="authenticity_token"]`},
			Name:      "token",
		}},
	}}
	e := New(&fakeStore{}, Config{RPS: 50, Concurrency: 2, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
	if !strings.Contains(res.Findings[0].Evidence, "tok123") {
		t.Errorf("expected extracted value, got %q", res.Findings[0].Evidence)
	}
}

func TestSSLCertMatcher(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	tmpl := domain.Template{ID: "ssl-test", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.SSL = []domain.SSLRequest{{
		Address: "{{Host}}",
		Matchers: []domain.Matcher{
			{Type: "word", Part: "issuer_dn", Words: []string{"Acme Co"}},
		},
		Extractors: []domain.Extractor{{Type: "json", JSON: []string{".subject_an"}}},
	}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("ssl: expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
	t.Logf("evidence: %s", res.Findings[0].Evidence)
}

func TestSSLVersionAndCipher(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	tmpl := domain.Template{ID: "ssl-ver", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.SSL = []domain.SSLRequest{{
		Address:    "{{Host}}",
		MinVersion: "tls12",
		MaxVersion: "tls13",
		Extractors: []domain.Extractor{{Type: "dsl", DSL: []string{"tls_version, cipher"}}},
	}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("ssl version: expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
	ev := res.Findings[0].Evidence
	if !strings.Contains(ev, "tls1") {
		t.Errorf("expected tls_version in evidence, got %q", ev)
	}
	if !strings.Contains(ev, "TLS_") && !strings.Contains(ev, "TLS") {
		t.Errorf("expected cipher in evidence, got %q", ev)
	}
}
