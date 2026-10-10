package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"wscan/internal/domain"
)

func pathRecorder() (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		s := append([]string(nil), paths...)
		sort.Strings(s)
		return s
	}
}

func payloadTemplate(attack string) domain.Template {
	tmpl := domain.Template{ID: "pl", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{{
		Method: "GET",
		Path:   domain.StringList{"{{BaseURL}}/{{A}}/{{B}}"},
		Attack: attack,
		Payloads: domain.PayloadSet{
			"A": {Values: []string{"1", "2"}},
			"B": {Values: []string{"x", "y"}},
		},
		Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}},
	}}
	return tmpl
}

func runPaths(t *testing.T, attack string) []string {
	srv, getPaths := pathRecorder()
	defer srv.Close()
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 8, TimeoutSeconds: 5})
	_, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{payloadTemplate(attack)})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return getPaths()
}

func TestPayloadsClusterbomb(t *testing.T) {
	got := runPaths(t, "clusterbomb")
	want := []string{"/1/x", "/1/y", "/2/x", "/2/y"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("clusterbomb paths = %v, want %v", got, want)
	}
}

func TestPayloadsPitchfork(t *testing.T) {
	got := runPaths(t, "pitchfork")
	want := []string{"/1/x", "/2/y"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("pitchfork paths = %v, want %v", got, want)
	}
}
