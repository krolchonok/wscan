package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"wscan/internal/domain"
)

// TestCVE202128480NonExchangeTargetIsQuietNotAnError reproduces "Ошибка
// проверки: CVE-2021-28480: flow script: TypeError: Cannot read property
// 'toLowerCase' of undefined". On a non-Exchange target, http(1)'s internal
// matcher (status 302 + x-feserver header) never passes, so the `servername`
// extractor never runs and template.servername stays undefined — the flow
// script then crashes on `servername.toLowerCase()` with no null guard. Real
// nuclei runs the identical goja flow script and hits the identical
// TypeError on the identical input; that's nuclei's own "not vulnerable"
// signal here, not a defect in our engine, so it must not surface as a check
// error (see isBenignFlowChainBreak).
func TestCVE202128480NonExchangeTargetIsQuietNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404) // plain non-Exchange host: no 302, no x-feserver header
	}))
	defer srv.Close()

	tmpl := loadUpstreamHTTPTemplate(t, "cves/2021", "CVE-2021-28480.yaml")
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("non-Exchange target must not surface the chained-undefined TypeError as a check error, got: %v", res.Errors)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("non-Exchange target must not match, got %d findings", len(res.Findings))
	}
}

// TestCVE202224637NonVulnerableTargetIsQuietNotAnError reproduces "Ошибка
// проверки: CVE-2022-24637: javascript: TypeError: Cannot read property '1'
// of undefined" — the same chained-undefined pattern as CVE-2021-28480, one
// level down: inside a javascript: block (not the flow: script itself).
// http(2)'s own internal regex extractor never finds the expected cache-file
// content on a non-vulnerable target, so `serobj` is empty and
// `serobj.substring(...).match(/.../)[1]` throws with no null guard. See
// isBenignUndefinedPropertyAccess, the same helper isBenignFlowChainBreak
// delegates to.
func TestCVE202224637NonVulnerableTargetIsQuietNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	tmpl := loadUpstreamHTTPTemplate(t, "cves/2022", "CVE-2022-24637.yaml")
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("non-vulnerable target must not surface the chained-undefined TypeError as a check error, got: %v", res.Errors)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("non-vulnerable target must not match, got %d findings", len(res.Findings))
	}
}

// TestCVE20263055OutOfRangeSecondBlockIsQuiet reproduces "Ошибка проверки:
// CVE-2026-3055: flow http(2): no such block (template has 1)". The real,
// unmodified upstream template's flow is "http(1) || http(2)" but it defines
// only one http: block (its two request alternatives live inside that one
// block's own raw: list, gated by stop-at-first-match) — so http(2) is
// always out of range. Real nuclei's flow executor treats an out-of-range id
// as a quiet false (see TestFlowOutOfRangeIndexIsQuietAndKeepsGoing), so this
// must not surface as a check error on every single scan of this template.
func TestCVE20263055OutOfRangeSecondBlockIsQuiet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	tmpl := loadUpstreamHTTPTemplate(t, "cves/2026", "CVE-2026-3055.yaml")
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("http(2)'s out-of-range reference must not surface as a check error, got: %v", res.Errors)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("non-vulnerable target must not match, got %d findings", len(res.Findings))
	}
}

// Negative: a genuine flow-script defect (not the undefined-chain pattern)
// must still be reported — isBenignFlowChainBreak must not swallow real bugs.
func TestIsBenignFlowChainBreakDoesNotMatchOtherErrors(t *testing.T) {
	cases := []struct {
		msg    string
		benign bool
	}{
		{"ReferenceError: javascript is not defined", false},
		{"TypeError: foo is not a function", false},
		{"TypeError: Cannot read property 'toLowerCase' of undefined", true},
		{"TypeError: Cannot read property 'replace' of undefined or null", true},
	}
	for _, c := range cases {
		got := isBenignFlowChainBreak(&testError{c.msg})
		if got != c.benign {
			t.Errorf("isBenignFlowChainBreak(%q) = %v, want %v", c.msg, got, c.benign)
		}
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
