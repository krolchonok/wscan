package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"wscan/internal/domain"
)

func writeTpl(t *testing.T, dir, name, body string) {
	p := filepath.Join(dir, "nuclei-templates", name)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowChains(t *testing.T) {
	// Server returns the path so each template can match its own endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer srv.Close()
	lib := t.TempDir()
	writeTpl(t, lib, "a.yaml", `
id: ref-a
info: {name: a, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/a-ok"]
    matchers:
      - type: word
        words: ["path=/a-ok"]
`)
	writeTpl(t, lib, "b.yaml", `
id: sub-b
info: {name: b, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/b-ok"]
    matchers:
      - type: word
        words: ["path=/b-ok"]
`)
	wf := domain.Template{ID: "wf", Compatible: true, Risk: "active"}
	wf.Workflows = []domain.WorkflowEntry{{
		Template:     "a.yaml",
		Subtemplates: []domain.WorkflowEntry{{Template: "b.yaml"}},
	}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5, LibraryDir: lib})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{wf})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	ids := map[string]bool{}
	for _, f := range res.Findings {
		ids[f.TemplateID] = true
	}
	if !ids["ref-a"] || !ids["sub-b"] {
		t.Fatalf("workflow: expected ref-a and sub-b, got %v (errs=%v)", res.Findings, res.Errors)
	}
}

func TestWorkflowNoMatchNoSub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	lib := t.TempDir()
	writeTpl(t, lib, "a.yaml", "id: ref-a\ninfo: {name: a, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/a-ok\"]\n    matchers:\n      - type: word\n        words: [\"never-present\"]\n")
	writeTpl(t, lib, "b.yaml", "id: sub-b\ninfo: {name: b, severity: info}\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/b\"]\n    matchers:\n      - type: status\n        status: [404]\n")
	wf := domain.Template{ID: "wf", Compatible: true, Risk: "active"}
	wf.Workflows = []domain.WorkflowEntry{{Template: "a.yaml", Subtemplates: []domain.WorkflowEntry{{Template: "b.yaml"}}}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5, LibraryDir: lib})
	res, _ := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{wf})
	if len(res.Findings) != 0 {
		t.Fatalf("workflow: expected 0 findings (parent didn't match), got %v", res.Findings)
	}
}
