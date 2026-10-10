package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wscan/internal/domain"
	"wscan/internal/oast"
)

func oastTemplate() domain.Template {
	tmpl := domain.Template{ID: "oast-test", Compatible: true, Risk: "active"}
	tmpl.Info.Name = "oast test"
	tmpl.Info.Severity = "critical"
	tmpl.HTTP = []domain.HTTPRequest{{
		Method:            "POST",
		Path:              domain.StringList{"{{BaseURL}}/inject"},
		Body:              "cb=" + oast.Placeholder,
		MatchersCondition: "and",
		Matchers: []domain.Matcher{
			{Type: "word", Part: "interactsh_protocol", Words: []string{"http"}},
		},
	}}
	return tmpl
}

func TestOASTConfirmedFinding(t *testing.T) {
	// Target simulates a vulnerable host: on receiving the payload it performs the
	// out-of-band callback (as injected command/SSRF would).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if i := strings.Index(string(b), "cb="); i >= 0 {
			_, _ = http.Get("http://" + strings.TrimSpace(string(b)[i+3:]))
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("queued"))
	}))
	defer srv.Close()

	store := &fakeStore{}
	e := New(store, Config{RPS: 50, Concurrency: 4, TimeoutSeconds: 5, OAST: true, OASTHost: "127.0.0.1"})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{oastTemplate()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 OAST-confirmed finding, got %d (errors: %v)", len(res.Findings), res.Errors)
	}
}

func TestOASTNoCallbackNoFinding(t *testing.T) {
	// Target does NOT call back: the OOB matcher must stay false (no false positive).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("http here is in the body but no callback happened"))
	}))
	defer srv.Close()

	store := &fakeStore{}
	e := New(store, Config{RPS: 50, Concurrency: 4, TimeoutSeconds: 5, OAST: true, OASTHost: "127.0.0.1"})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{oastTemplate()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings without callback, got %d", len(res.Findings))
	}
}

func TestOASTDisabledNoFinding(t *testing.T) {
	// With OAST off, OOB templates run but never match (unconfirmable) — no FP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if i := strings.Index(string(b), "cb="); i >= 0 {
			_, _ = http.Get("http://" + strings.TrimSpace(string(b)[i+3:]))
		}
		_, _ = w.Write([]byte("queued http"))
	}))
	defer srv.Close()

	store := &fakeStore{}
	e := New(store, Config{RPS: 50, Concurrency: 4, TimeoutSeconds: 5, OAST: false})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{oastTemplate()})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings with OAST disabled, got %d", len(res.Findings))
	}
}
