package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"wscan/internal/domain"
)

// echoServer reflects method, path, a header and the body so tests can confirm
// that variable/raw substitution actually reached the wire.
func echoServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "method=%s path=%s xtest=%s body=%s", r.Method, r.URL.RequestURI(), r.Header.Get("X-Test"), string(b))
	}))
}

func TestVariablesInPathAndHeader(t *testing.T) {
	srv := echoServer()
	defer srv.Close()
	tmpl := domain.Template{ID: "vars-test", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.Variables = domain.VariableList{{Name: "marker", Value: "SENTINEL123"}}
	tmpl.HTTP = []domain.HTTPRequest{{
		Method:            "GET",
		Path:              domain.StringList{"{{BaseURL}}/x/{{marker}}"},
		Headers:           map[string]string{"X-Test": "{{marker}}"},
		MatchersCondition: "and",
		Matchers: []domain.Matcher{
			{Type: "word", Part: "body", Words: []string{"path=/x/SENTINEL123"}},
			{Type: "word", Part: "body", Words: []string{"xtest=SENTINEL123"}},
		},
	}}
	store := &fakeStore{}
	e := New(store, Config{RPS: 50, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding (variables substituted), got %d errs=%v", len(res.Findings), res.Errors)
	}
}

func TestRawRequest(t *testing.T) {
	srv := echoServer()
	defer srv.Close()
	tmpl := domain.Template{ID: "raw-test", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.Variables = domain.VariableList{{Name: "marker", Value: "RAWSENT"}}
	tmpl.HTTP = []domain.HTTPRequest{{
		Raw:               domain.StringList{"POST /raw-ep?q={{marker}} HTTP/1.1\nHost: {{Hostname}}\nX-Test: {{marker}}\n\npayload={{marker}}"},
		MatchersCondition: "and",
		Matchers: []domain.Matcher{
			{Type: "word", Part: "body", Words: []string{"method=POST"}},
			{Type: "word", Part: "body", Words: []string{"path=/raw-ep?q=RAWSENT"}},
			{Type: "word", Part: "body", Words: []string{"xtest=RAWSENT"}},
			{Type: "word", Part: "body", Words: []string{"body=payload=RAWSENT"}},
		},
	}}
	store := &fakeStore{}
	e := New(store, Config{RPS: 50, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding (raw request), got %d errs=%v", len(res.Findings), res.Errors)
	}
}
