package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"wscan/internal/domain"
)

func codeTemplate(req domain.CodeRequest) domain.Template {
	tmpl := domain.Template{ID: "code-test", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.Code = []domain.CodeRequest{req}
	return tmpl
}

func TestCodeExecDisabledByDefault(t *testing.T) {
	tmpl := codeTemplate(domain.CodeRequest{
		Engine:   []string{"sh"},
		Source:   "echo hello",
		Matchers: []domain.Matcher{{Type: "word", Part: "data", Words: []string{"hello"}}},
	})
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5}) // AllowCodeExec defaults false
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"example.com"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("code exec must be refused by default, got %d findings", len(res.Findings))
	}
	if len(res.Errors) != 0 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "отключено") {
		t.Fatalf("expected skip without errors: errors=%v skipped=%v", res.Errors, res.Skipped)
	}
}

func TestCodeExecRunsWhenAllowed(t *testing.T) {
	tmpl := codeTemplate(domain.CodeRequest{
		Engine:     []string{"sh"},
		Source:     "echo wscan-code-ok",
		Matchers:   []domain.Matcher{{Type: "word", Part: "data", Words: []string{"wscan-code-ok"}}},
		Extractors: []domain.Extractor{{Type: "regex", Regex: []string{"wscan-([a-z]+)-ok"}}},
	})
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"example.com"}, AllowCodeExec: true}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
	if res.Findings[0].Protocol != "code" {
		t.Fatalf("protocol=%q, want code", res.Findings[0].Protocol)
	}
}

func TestCodeExecNoMatchNoFinding(t *testing.T) {
	tmpl := codeTemplate(domain.CodeRequest{
		Engine:   []string{"sh"},
		Source:   "echo nothing-relevant",
		Matchers: []domain.Matcher{{Type: "word", Part: "data", Words: []string{"will-not-match"}}},
	})
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"example.com"}, AllowCodeExec: true}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(res.Findings))
	}
}

func TestCodeExecInterpreterNotFound(t *testing.T) {
	tmpl := codeTemplate(domain.CodeRequest{
		Engine: []string{"definitely-not-a-real-interpreter-xyz"},
		Source: "irrelevant",
	})
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"example.com"}, AllowCodeExec: true}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(res.Findings))
	}
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "no interpreter found") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a 'no interpreter found' error, got errors=%v", res.Errors)
	}
}

func TestCodeExecRespectsTimeout(t *testing.T) {
	tmpl := codeTemplate(domain.CodeRequest{
		Engine:   []string{"sh"},
		Source:   "sleep 5; echo too-late",
		Matchers: []domain.Matcher{{Type: "word", Part: "data", Words: []string{"too-late"}}},
	})
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 1})
	start := time.Now()
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"example.com"}, AllowCodeExec: true}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("code: did not respect timeout, took %v", elapsed)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("timed-out script must not match, got %d findings", len(res.Findings))
	}
}
