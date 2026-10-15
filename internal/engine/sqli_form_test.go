package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func hitsByTechnique(hits []SQLiFormHit) map[string]SQLiFormHit {
	out := map[string]SQLiFormHit{}
	for _, h := range hits {
		out[h.Parameter] = h
	}
	return out
}

func TestSQLiFormErrorBased(t *testing.T) {
	html := `<html><body><form action="/search/run" method="get"><input name="q" value="widgets"></form></body></html>`
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/page" {
			w.Write([]byte(html))
			return
		}
		q := r.URL.Query().Get("q")
		if strings.ContainsAny(q, `'"\`) {
			w.Write([]byte("You have an error in your SQL syntax near MySQL"))
			return
		}
		w.Write([]byte("results for " + q))
	}))
	defer page.Close()
	result, err := ScanSQLiForms(context.Background(), SQLiFormOptions{URL: page.URL + "/page"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Forms != 1 {
		t.Fatalf("expected 1 form, got %+v", result)
	}
	hits := hitsByTechnique(result.Hits)
	h, ok := hits["q"]
	if !ok || h.Technique != "error-based" || h.DBMS != "MySQL/MariaDB" {
		t.Fatalf("expected error-based MySQL hit on q, got %+v (ok=%v)", h, ok)
	}
}

func TestSQLiFormBooleanBased(t *testing.T) {
	// Classic blind SQLi on a numeric id: "OR 1=1" keeps the same row visible
	// (response ~= baseline), "OR 1=2" hides it (response clearly differs);
	// neither error-based payload nor the quoted boolean pair changes
	// anything, so the numeric pair is what must trigger the finding.
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/item" {
			switch r.URL.Query().Get("id") {
			case "1", "1 OR 1=1-- -":
				w.Write([]byte("item 1: Widget A"))
			case "1 OR 1=2-- -":
				w.Write([]byte("no results"))
			default:
				w.Write([]byte("item 1: Widget A"))
			}
			return
		}
		w.Write([]byte(`<html><body><form action="/item" method="get"><input name="id" value="1"></form></body></html>`))
	}))
	defer page.Close()
	result, err := ScanSQLiForms(context.Background(), SQLiFormOptions{URL: page.URL + "/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hits := hitsByTechnique(result.Hits)
	h, ok := hits["id"]
	if !ok || h.Technique != "boolean-based blind" {
		t.Fatalf("expected boolean-based hit on id, got %+v (ok=%v); all hits=%+v", h, ok, result.Hits)
	}
}

func TestSQLiFormTimeBased(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/item" && r.Method == http.MethodGet && r.URL.Query().Get("id") != "" {
			id := r.URL.Query().Get("id")
			if strings.Contains(id, "SLEEP(4)") {
				time.Sleep(4 * time.Second)
			}
			w.Write([]byte("item " + id))
			return
		}
		w.Write([]byte(`<html><body><form action="/item" method="get"><input name="id" value="1"></form></body></html>`))
	}))
	defer page.Close()
	result, err := ScanSQLiForms(context.Background(), SQLiFormOptions{URL: page.URL + "/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hits := hitsByTechnique(result.Hits)
	h, ok := hits["id"]
	if !ok || h.Technique != "time-based blind" || h.DBMS != "MySQL/MariaDB" {
		t.Fatalf("expected time-based MySQL hit on id, got %+v (ok=%v)", h, ok)
	}
}

func TestSQLiFormNoVulnerability(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte(`<html><body><form action="/search" method="get"><input name="q" value="widgets"></form></body></html>`))
			return
		}
		w.Write([]byte("results for " + r.URL.Query().Get("q")))
	}))
	defer page.Close()
	result, err := ScanSQLiForms(context.Background(), SQLiFormOptions{URL: page.URL + "/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Hits) != 0 {
		t.Fatalf("expected no hits on a benign echo form, got %+v", result.Hits)
	}
}

func TestSQLiFormSkipsMultipartAndInputValidation(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><form action="/upload" method="post" enctype="multipart/form-data"><input name="file" type="file"></form></body></html>`))
	}))
	defer page.Close()
	if _, err := ScanSQLiForms(context.Background(), SQLiFormOptions{URL: page.URL + "/"}, nil); err == nil {
		t.Fatal("expected error when only a multipart form is present")
	}
	for _, o := range []SQLiFormOptions{{URL: "file:///etc/passwd"}, {URL: "http://user:secret@example.org"}, {URL: "http://example.org", VirtualHost: "a b"}} {
		if _, err := ScanSQLiForms(context.Background(), o, nil); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
}

func TestSQLiFormRejectsCrossOriginAction(t *testing.T) {
	var attacked bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { attacked = true }))
	defer other.Close()
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<form action="` + other.URL + `/admin" method="post"><input name="q"></form>`))
	}))
	defer page.Close()

	if _, err := ScanSQLiForms(context.Background(), SQLiFormOptions{URL: page.URL}, nil); err == nil {
		t.Fatal("expected cross-origin form to be rejected")
	}
	if attacked {
		t.Fatal("cross-origin form action received an active probe")
	}
}
