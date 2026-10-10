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

// flowServer serves one status code per path ("/1", "/2", ...) and records
// which paths were actually hit, so tests can check both what a flow script
// found and which blocks it short-circuited past.
func flowServer(status map[string]int) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()
		code := status[r.URL.Path]
		if code == 0 {
			code = 200
		}
		w.WriteHeader(code)
	}))
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		s := append([]string(nil), hits...)
		sort.Strings(s)
		return s
	}
}

func flowHTTPBlock(path string) domain.HTTPRequest {
	return domain.HTTPRequest{
		Method:   "GET",
		Path:     domain.StringList{"{{BaseURL}}" + path},
		Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}},
	}
}

func TestFlowAndShortCircuitsSecondCall(t *testing.T) {
	// http(1) fails to match (404) so "&&" must short-circuit: http(2) is
	// never called, and there must be no finding.
	srv, hits := flowServer(map[string]int{"/1": 404, "/2": 200})
	defer srv.Close()
	tmpl := domain.Template{ID: "flow-and", Compatible: true, Risk: "active", Flow: "http(1) && http(2)"}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{flowHTTPBlock("/1"), flowHTTPBlock("/2")}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings (short-circuited), got %d: %+v", len(res.Findings), res.Findings)
	}
	if got := hits(); len(got) != 1 || got[0] != "/1" {
		t.Fatalf("expected only /1 to be hit, got %v", got)
	}
}

func TestFlowOrCallsSecondWhenFirstMisses(t *testing.T) {
	// http(1) misses, "||" must still try http(2), which matches.
	srv, hits := flowServer(map[string]int{"/1": 404, "/2": 200})
	defer srv.Close()
	tmpl := domain.Template{ID: "flow-or", Compatible: true, Risk: "active", Flow: "http(1) || http(2)"}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{flowHTTPBlock("/1"), flowHTTPBlock("/2")}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding from http(2), got %d: %+v", len(res.Findings), res.Findings)
	}
	got := hits()
	if len(got) != 2 {
		t.Fatalf("expected both /1 and /2 to be hit, got %v", got)
	}
}

func TestFlowMultilineScriptWithCondition(t *testing.T) {
	// A multi-line flow script (not just a one-liner expression) with an
	// explicit if — matching the "flow: |" block-scalar shape templates use.
	srv, _ := flowServer(map[string]int{"/1": 200, "/2": 200})
	defer srv.Close()
	tmpl := domain.Template{ID: "flow-multiline", Compatible: true, Risk: "active", Flow: "if (http(1)) {\n  http(2);\n}\n"}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{flowHTTPBlock("/1"), flowHTTPBlock("/2")}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(res.Findings), res.Findings)
	}
}

func TestFlowNoArgsRunsAllBlocksInOrder(t *testing.T) {
	// "http()" with no indices means "run every http block, in order".
	srv, hits := flowServer(nil)
	defer srv.Close()
	tmpl := domain.Template{ID: "flow-all", Compatible: true, Risk: "active", Flow: "http()"}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{flowHTTPBlock("/1"), flowHTTPBlock("/2"), flowHTTPBlock("/3")}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(res.Findings))
	}
	if got := hits(); len(got) != 3 {
		t.Fatalf("expected all 3 blocks hit, got %v", got)
	}
}

// TestFlowOutOfRangeIndexIsQuietAndKeepsGoing matches real nuclei's own
// flow_internal.go requestExecutor: an invalid/out-of-range flow request id
// is logged internally (debug-only) and the call just returns false — it is
// NOT surfaced to the user as a check error (confirmed against nuclei's
// upstream source: an unknown id goes through f.ctx.LogError, never through
// the result/finding path). Some real upstream templates genuinely reference
// an id their own flow doesn't define — e.g. CVE-2026-3055.yaml's
// "http(1) || http(2)" against a single http: block whose own
// stop-at-first-match already covers both request alternatives — and these
// must not flood "Ошибка проверки" on every scan. What must still hold is
// the control-flow guarantee: the bad reference doesn't abort the rest of
// the script.
func TestFlowOutOfRangeIndexIsQuietAndKeepsGoing(t *testing.T) {
	srv, hits := flowServer(nil)
	defer srv.Close()
	tmpl := domain.Template{ID: "flow-oob", Compatible: true, Risk: "active", Flow: "http(5); http(1);"}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{flowHTTPBlock("/1")}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding from http(1) despite the earlier bad index, got %d", len(res.Findings))
	}
	if got := hits(); len(got) != 1 || got[0] != "/1" {
		t.Fatalf("expected only /1 to be hit, got %v", got)
	}
	for _, errMsg := range res.Errors {
		if strings.Contains(errMsg, "flow-oob") {
			t.Fatalf("an out-of-range flow index must not surface as a check error, got: %v", res.Errors)
		}
	}
}

func TestFlowCallsTCPBlock(t *testing.T) {
	_, port := bannerListener(t, []byte("FLOW-TCP-OK"))
	tmpl := domain.Template{ID: "flow-tcp", Compatible: true, Risk: "active", Flow: "tcp(1)"}
	tmpl.Info.Severity = "info"
	tmpl.TCP = []domain.TCPRequest{{
		Inputs:   []domain.TCPInput{{Data: "ping"}},
		Host:     domain.StringList{"{{Hostname}}"},
		Port:     domain.IntList{port},
		Matchers: []domain.Matcher{{Type: "word", Part: "data", Words: []string{"FLOW-TCP-OK"}}},
	}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"127.0.0.1"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding from tcp(1), got %d errs=%v", len(res.Findings), res.Errors)
	}
}

func TestFlowNamedHTTPBlocks(t *testing.T) {
	// http("leak") must resolve by yaml id, not ToInteger("leak")==0.
	srv, hits := flowServer(map[string]int{"/leak": 200, "/exploit": 200})
	defer srv.Close()
	tmpl := domain.Template{
		ID: "flow-named", Compatible: true, Risk: "active",
		Flow: `http("leak") && http("exploit")`,
	}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{
		{ID: "leak", Method: "GET", Path: domain.StringList{"{{BaseURL}}/leak"}, Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}}},
		{ID: "exploit", Method: "GET", Path: domain.StringList{"{{BaseURL}}/exploit"}, Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}}},
	}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings from named http(), got %d errs=%v", len(res.Findings), res.Errors)
	}
	got := hits()
	if len(got) != 2 || got[0] != "/exploit" && (got[0] != "/leak" && got[1] != "/leak") {
		// order of hits is call order: leak then exploit; sort makes them alphabetical
		want := []string{"/exploit", "/leak"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("hits=%v want both /leak and /exploit", got)
		}
	}
}

func TestFlowIterate(t *testing.T) {
	srv, hits := flowServer(map[string]int{"/a": 200, "/b": 200})
	defer srv.Close()
	tmpl := domain.Template{
		ID: "flow-iter", Compatible: true, Risk: "active",
		Flow: `
			for (let p of iterate(template.paths)) {
				set("p", p);
				http(1);
			}
		`,
	}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{{
		Method:   "GET",
		Path:     domain.StringList{"{{BaseURL}}/{{p}}"},
		Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}},
	}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	// Seed vars via a tiny wrapper: execFlow reads vars from evalVariables;
	// inject through template Variables won't give a list. Use Flow set before
	// iterate by pre-stuffing via a custom scan path — instead put paths in
	// variables as unused and set them in flow first.
	tmpl.Flow = `
		template.paths = ["a", "b"];
		for (let p of iterate(template.paths)) {
			set("p", p);
			http(1);
		}
	`
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings from iterate, got %d errs=%v hits=%v", len(res.Findings), res.Errors, hits())
	}
}

func TestFlowStopSkipsLaterBlocks(t *testing.T) {
	srv, hits := flowServer(map[string]int{"/1": 200, "/2": 200})
	defer srv.Close()
	tmpl := domain.Template{
		ID: "flow-stop", Compatible: true, Risk: "active",
		Flow: "http(1);\nstop();\nhttp(2);\n",
	}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{flowHTTPBlock("/1"), flowHTTPBlock("/2")}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding before stop, got %d: %+v", len(res.Findings), res.Findings)
	}
	if got := hits(); len(got) != 1 || got[0] != "/1" {
		t.Fatalf("expected only /1 after stop(), got %v", got)
	}
	for _, errMsg := range res.Errors {
		if strings.Contains(errMsg, "flow script") {
			t.Fatalf("stop() must not be reported as a script error, got %v", res.Errors)
		}
	}
}

func TestFlowHTTPResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("FLOW-BODY-MARKER"))
	}))
	defer srv.Close()
	tmpl := domain.Template{
		ID: "flow-body", Compatible: true, Risk: "active",
		Flow: `
			let r = http(1);
			if (r && r.body && r.body.indexOf("FLOW-BODY-MARKER") !== -1) {
				http(2);
			}
		`,
	}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{
		{
			Method: "GET", Path: domain.StringList{"{{BaseURL}}/probe"},
			Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}},
		},
		{
			Method: "GET", Path: domain.StringList{"{{BaseURL}}/confirm"},
			Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}},
		},
	}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected 2 findings via http(1).body gate, got %d errs=%v", len(res.Findings), res.Errors)
	}
}

func TestFlowInternalGateStillTruthyForAnd(t *testing.T) {
	// http(1) internal-only match must be truthy for && so http(2) still runs,
	// but must not emit a finding of its own.
	srv, hits := flowServer(map[string]int{"/1": 202, "/2": 200})
	defer srv.Close()
	tmpl := domain.Template{
		ID: "flow-internal-and", Compatible: true, Risk: "active",
		Flow: "http(1) && http(2)",
	}
	tmpl.Info.Severity = "info"
	tmpl.HTTP = []domain.HTTPRequest{
		{
			Method: "GET", Path: domain.StringList{"{{BaseURL}}/1"},
			Matchers: []domain.Matcher{{Type: "status", Status: []int{202}, Internal: true}},
		},
		flowHTTPBlock("/2"),
	}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding from http(2) only, got %d: %+v", len(res.Findings), res.Findings)
	}
	if got := hits(); len(got) != 2 {
		t.Fatalf("expected both steps hit, got %v", got)
	}
}

func TestHTTPInternalMatcherNoFinding(t *testing.T) {
	// Mirrors run#22 FPs: multi-step template whose first request only has
	// internal: true matchers (e.g. status 403/404 gate). That step must not
	// emit a finding by itself.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/wp-json":
			http.NotFound(w, r)
		case "/wp-json/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"x","url":"y","home":"z","description":"d"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	tmpl := domain.Template{ID: "http-internal-gate", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "medium"
	tmpl.HTTP = []domain.HTTPRequest{
		{
			Method: "GET", Path: domain.StringList{"{{BaseURL}}/wp-json"},
			Matchers: []domain.Matcher{{Type: "status", Status: []int{403, 404}, Internal: true}},
		},
		{
			Method: "GET", Path: domain.StringList{"{{BaseURL}}/wp-json/"},
			MatchersCondition: "and",
			Matchers: []domain.Matcher{
				{Type: "word", Part: "body", Words: []string{`"name":`, `"url":`}, Condition: "and"},
				{Type: "status", Status: []int{200}},
			},
		},
	}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Only the second (non-internal) request should produce a finding.
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding from step 2, got %d: %+v", len(res.Findings), res.Findings)
	}
	if !strings.Contains(res.Findings[0].MatchedAt, "/wp-json/") {
		t.Fatalf("matched_at=%q want second request path", res.Findings[0].MatchedAt)
	}

	// Gate-only template: internal matchers alone must never find.
	tmpl2 := domain.Template{ID: "http-internal-only", Compatible: true, Risk: "active"}
	tmpl2.Info.Severity = "low"
	tmpl2.HTTP = []domain.HTTPRequest{{
		Method: "GET", Path: domain.StringList{"{{BaseURL}}/wp-json"},
		Matchers: []domain.Matcher{{Type: "status", Status: []int{404}, Internal: true}},
	}}
	res2, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{tmpl2})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res2.Findings) != 0 {
		t.Fatalf("internal-only HTTP matchers must not emit findings, got %d", len(res2.Findings))
	}
}
