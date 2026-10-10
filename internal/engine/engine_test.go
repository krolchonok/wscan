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

type fakeStore struct {
	findings      []domain.Finding
	services      []domain.Service
	failureCounts map[string]int
}

func (f *fakeStore) StartRun(context.Context, int64) (int64, error) { return 1, nil }
func (f *fakeStore) SaveFinding(_ context.Context, _ int64, x domain.Finding) error {
	f.findings = append(f.findings, x)
	return nil
}
func (f *fakeStore) FinishRun(context.Context, int64, string) error { return nil }
func (f *fakeStore) SaveService(_ context.Context, _ int64, s domain.Service) error {
	f.services = append(f.services, s)
	return nil
}
func (f *fakeStore) RecordAttempt(_ context.Context, _ int64, _, username, _ string, success bool) error {
	if !success {
		if f.failureCounts == nil {
			f.failureCounts = map[string]int{}
		}
		f.failureCounts[username]++
	}
	return nil
}
func (f *fakeStore) RecentFailureCount(_ context.Context, _ int64, username string, _ time.Time) (int, error) {
	return f.failureCounts[username], nil
}

func TestEngineNativeTemplate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><title>Welcome Admin</title></html>"))
	}))
	defer srv.Close()

	tmpl := domain.Template{ID: "test-native", Compatible: true, Risk: "read-only"}
	tmpl.Info.Name = "native test"
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{{
		Method:            "GET",
		Path:              domain.StringList{"{{BaseURL}}/"},
		MatchersCondition: "and",
		Matchers: []domain.Matcher{
			{Type: "status", Status: []int{200}},
			{Type: "word", Part: "body", Words: []string{"Welcome Admin"}},
			{Type: "dsl", DSL: []string{`contains(to_lower(body), "welcome") && status_code == 200`}},
			{Type: "regex", Part: "header", Regex: []string{`nginx/[0-9.]+`}},
		},
		Extractors: []domain.Extractor{
			{Type: "regex", Part: "header", Name: "server", Regex: []string{`nginx/[0-9.]+`}},
		},
	}}

	store := &fakeStore{}
	e := New(store, Config{RPS: 50, Concurrency: 4, TimeoutSeconds: 5})
	p := domain.Project{ID: 1, Targets: []string{srv.URL}}
	res, err := e.Scan(context.Background(), p, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d (errors: %v)", len(res.Findings), res.Errors)
	}
	if !strings.Contains(res.Findings[0].Evidence, "nginx/1.24.0") {
		t.Errorf("expected extractor evidence with server version, got %q", res.Findings[0].Evidence)
	}
}

func TestEngineNoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	tmpl := domain.Template{ID: "test-nofp", Compatible: true, Risk: "read-only"}
	tmpl.HTTP = []domain.HTTPRequest{{
		Method:            "GET",
		Path:              domain.StringList{"{{BaseURL}}/"},
		MatchersCondition: "and",
		Matchers: []domain.Matcher{
			{Type: "status", Status: []int{200}},
			{Type: "dsl", DSL: []string{`contains(body, "Welcome")`}},
		},
	}}
	store := &fakeStore{}
	e := New(store, Config{RPS: 50, Concurrency: 2, TimeoutSeconds: 5})
	p := domain.Project{ID: 1, Targets: []string{srv.URL}}
	res, err := e.Scan(context.Background(), p, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("want 0 findings on 404, got %d", len(res.Findings))
	}
}

func TestEngineExtractorOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`adafruit_key = "abcdefghijklmnopqrstuvwxyz012345"`))
	}))
	defer srv.Close()

	tmpl := domain.Template{ID: "extractor-only", Compatible: true, Risk: "read-only"}
	tmpl.Info.Name = "token detector"
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{{
		Method: "GET",
		Path:   domain.StringList{"{{BaseURL}}/"},
		Extractors: []domain.Extractor{{
			Type:  "regex",
			Part:  "body",
			Regex: []string{`adafruit_key\s*=\s*"([a-z0-9]{32})"`},
			Group: 1,
		}},
	}}

	store := &fakeStore{}
	e := New(store, Config{RPS: 50, Concurrency: 2, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding from extractor-only template, got %d (errors: %v)", len(res.Findings), res.Errors)
	}
	if !strings.Contains(res.Findings[0].Evidence, "abcdefghijklmnopqrstuvwxyz012345") {
		t.Errorf("expected extracted token in evidence, got %q", res.Findings[0].Evidence)
	}
}

func TestEngineExtractorOnlyNoHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nothing here"))
	}))
	defer srv.Close()

	tmpl := domain.Template{ID: "extractor-miss", Compatible: true, Risk: "read-only"}
	tmpl.HTTP = []domain.HTTPRequest{{
		Method: "GET",
		Path:   domain.StringList{"{{BaseURL}}/"},
		Extractors: []domain.Extractor{{
			Type:  "regex",
			Regex: []string{`secret_token_[A-Z]{10}`},
		}},
	}}
	e := New(&fakeStore{}, Config{RPS: 50, Concurrency: 2, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("want 0 findings when extractor misses, got %d", len(res.Findings))
	}
}

func TestEngineRunsManuallySelectedChecksRegardlessOfRisk(t *testing.T) {
	for _, risk := range []string{"read-only", "active", "intrusive"} {
		t.Run(risk, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()
			tmpl := domain.Template{ID: "selected-check", Compatible: true, Risk: risk}
			tmpl.HTTP = []domain.HTTPRequest{{Method: "POST", Path: domain.StringList{"{{BaseURL}}/"}, Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}}}}
			e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 1, TimeoutSeconds: 2})
			res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
			if err != nil || len(res.Findings) != 1 || len(res.Errors) != 0 {
				t.Fatalf("selected check was not executed: %+v, err=%v", res, err)
			}
		})
	}
}
