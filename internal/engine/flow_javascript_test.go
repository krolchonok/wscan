package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"wscan/internal/domain"
	tpl "wscan/internal/template"
)

func loadUpstreamHTTPTemplate(t *testing.T, sub, name string) domain.Template {
	t.Helper()
	for _, c := range []string{
		filepath.Join("..", "..", "library", "nuclei-templates", "http", sub),
		filepath.Join("library", "nuclei-templates", "http", sub),
	} {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			raw, err := os.ReadFile(filepath.Join(c, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			tm, err := tpl.ForExecution(raw, "http/"+sub+"/"+name)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			if !tm.Compatible {
				t.Fatalf("%s not compatible: %v", name, tm.Unsupported)
			}
			return tm
		}
	}
	t.Fatalf("library/nuclei-templates/http/%s/%s not found", sub, name)
	return domain.Template{}
}

// TestCookiesWithoutSecureFlowJavaScript reproduces "Ошибка проверки: ...:
// flow script: ReferenceError: javascript is not defined" — the real,
// unmodified upstream template's flow is literally `http(); javascript();`,
// and the javascript: step reads template.http_all_headers to find
// Set-Cookie lines missing the Secure attribute.
func TestCookiesWithoutSecureFlowJavaScript(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc123; Path=/")
		w.Header().Add("Set-Cookie", "csrf=xyz; Secure; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	tmpl := loadUpstreamHTTPTemplate(t, "misconfiguration", "cookies-without-secure.yaml")
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range res.Errors {
		t.Errorf("unexpected error: %s", e)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding (the non-secure 'session' cookie), got %d errs=%v", len(res.Findings), res.Errors)
	}
}
