package engine

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wscan/internal/domain"
	"wscan/internal/dsl"
	"wscan/internal/engine/js"
	"wscan/internal/libsync"
	"wscan/internal/oast"
	"wscan/internal/template"
)

type Saver interface {
	StartRun(context.Context, int64) (int64, error)
	SaveFinding(context.Context, int64, domain.Finding) error
	FinishRun(context.Context, int64, string) error
	SaveService(context.Context, int64, domain.Service) error
	// RecordAttempt/RecentFailureCount back SprayCredentials' lockout-safety
	// check (see spray.go) — not part of the template-scan Result pipeline.
	RecordAttempt(ctx context.Context, projectID int64, target, username, protocol string, success bool) error
	RecentFailureCount(ctx context.Context, projectID int64, username string, since time.Time) (int, error)
}

type Config struct {
	RPS, Concurrency, TimeoutSeconds int
	Complete                         bool
	LibraryDir                       string
	// OAST enables our own out-of-band collaborator so interactsh templates can
	// be confirmed natively. OASTHost overrides the callback host advertised to
	// targets (default: the scanner's detected outbound IP).
	OAST     bool
	OASTHost string
}

// code: requests are gated by domain.Project.AllowCodeExec (per project, not
// per engine instance — like RPS/Concurrency, ScanProgress reads it fresh
// off p on every call) rather than a Config field here: the one request
// type that shells out to a real external interpreter on the scanner's own
// machine instead of staying inside our native engine like everything
// else. Defaults to false (code: checks refused with a clear error) — the
// operator must opt in per project, and the TUI requires acknowledging a
// one-time warning before it can become true (internal/tui/settings.go).
// See internal/engine/code.go.
type Engine struct {
	store            Saver
	config           Config
	localPolicyCache *localPolicyCache
}
type Result struct {
	Coverage          []domain.CheckCoverage
	HostNames         map[string][]string
	RunID             int64
	Findings          []domain.Finding
	Errors            []string
	Skipped           []string
	Services          []domain.Service
	LiveHosts         []string
	TargetsScanned    int
	HTTPRequestsSaved int64
}

func New(s Saver, c Config) *Engine {
	if c.RPS < 1 {
		c.RPS = 5
	}
	if c.Concurrency < 1 {
		c.Concurrency = 4
	}
	if c.TimeoutSeconds < 1 {
		c.TimeoutSeconds = 10
	}
	return &Engine{store: s, config: c, localPolicyCache: &localPolicyCache{}}
}

// Scan runs the templates with no progress reporting.
func (e *Engine) Scan(ctx context.Context, p domain.Project, templates []domain.Template) (Result, error) {
	return e.ScanProgress(ctx, p, templates, nil)
}

// ScanProgress runs the templates, calling progress(done, total) as checks
// complete (throttled to ~100 updates) so the UI can show live progress.
func (e *Engine) ScanProgress(ctx context.Context, p domain.Project, templates []domain.Template, progress func(done, total int)) (Result, error) {
	// This project runs on its own native engine only — scans never shell out to
	// the external Nuclei binary. Templates whose features the native engine does
	// not support are already marked incompatible at parse time and skipped.
	runID, err := e.store.StartRun(ctx, p.ID)
	if err != nil {
		return Result{}, err
	}
	result := Result{RunID: runID, Services: append([]domain.Service(nil), p.Services...)}
	if !p.AllowCodeExec {
		enabled := make([]domain.Template, 0, len(templates))
		for _, t := range templates {
			if len(t.Code) > 0 {
				result.Skipped = append(result.Skipped, t.ID+": code: выполнение отключено в настройках проекта")
				continue
			}
			enabled = append(enabled, t)
		}
		templates = enabled
	}
	// Every javascript: check's goja VM derives its context from this same
	// ctx (execTemplate -> execJavaScript -> js.Run), so attaching the
	// discovered services here once makes discoveredPorts(host, name)
	// available everywhere without threading a new parameter through that
	// whole call chain — see js.WithDiscoveredServices's doc comment.
	ctx = js.WithDiscoveredServices(ctx, convertServicesForJS(p.Services))
	ctx = js.WithSSHInfoCache(ctx)
	status := "completed"
	defer func() { _ = e.store.FinishRun(context.Background(), runID, status) }()
	// Our own out-of-band collaborator, so interactsh templates are confirmed by
	// a real callback instead of being skipped. If it cannot start, OOB matchers
	// simply never fire (no false positives); the scan continues.
	var collab *oast.Collaborator
	if e.config.OAST {
		c, oerr := oast.Start(e.config.OASTHost)
		if oerr != nil {
			result.Errors = append(result.Errors, "OAST: "+oerr.Error())
		} else {
			collab = c
			defer collab.Close()
		}
	}
	rps, workers := e.config.RPS, e.config.Concurrency
	if p.RPS >= 0 {
		rps = p.RPS
	}
	if p.Concurrency > 0 {
		workers = p.Concurrency
	}
	if workers < 1 {
		workers = 1
	}
	// Hard ceiling: more goroutines than this only burns RAM; host gate / conn
	// pool already serialize dials per target.
	const maxWorkers = 64
	if workers > maxWorkers {
		workers = maxWorkers
	}
	gate := newHostGate(workers)
	sshGate := newHostGate(1)
	perHost := gate.maxHost
	// RPS 0 means "as fast as settings allow" in the UI — still apply a soft
	// ceiling so Connection: close churn cannot exhaust ephemeral ports.
	if rps == 0 {
		rps = perHost * 20
		if rps < 40 {
			rps = 40
		}
		if rps > 240 {
			rps = 240
		}
	}
	var rateTick <-chan time.Time
	if rps > 0 {
		limiter := time.NewTicker(max(time.Nanosecond, time.Second/time.Duration(rps)))
		defer limiter.Stop()
		rateTick = limiter.C
	}
	timeout := e.config.TimeoutSeconds
	if p.TimeoutSeconds > 0 {
		timeout = p.TimeoutSeconds
	}
	client := newScanHTTPClient(timeout, perHost)
	defer client.CloseIdleConnections()
	responseCache := newHTTPResponseCache()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, service := range p.Services {
		if err := e.store.SaveService(ctx, runID, service); err != nil {
			return result, err
		}
	}
	targets := p.Targets
	if p.UseDiscoveredTargets {
		targets = p.ScanTargets
	}
	result.TargetsScanned = len(targets)
	retries := p.Retries
	if retries < 0 {
		retries = 0
	}
	if retries > 10 {
		retries = 10
	}
	// Count the checks that will actually run so progress has a denominator.
	ipOnly := targetsAreAllIPs(targets)
	total := 0
	for _, target := range targets {
		for _, t := range templates {
			if template.Validate(t) == nil && !(ipOnly && skipTemplateOnIPTarget(t)) && databaseTemplateMatches(t, target, p.Services) {
				total++
			}
		}
	}
	if progress != nil {
		progress(0, total)
	}
	step := total / 100
	if step < 1 {
		step = 1
	}
	var done int64
	var progressMu sync.Mutex
	report := func() {
		if progress == nil || ctx.Err() != nil {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()
		d := atomic.AddInt64(&done, 1)
		if int(d)%step == 0 || int(d) == total {
			progress(int(d), total)
		}
	}

	type scanJob struct {
		target string
		tmpl   domain.Template
	}
	// Fixed worker pool + bounded queue: avoids spawning one goroutine per
	// template (thousands) while still keeping workers busy.
	jobs := make(chan scanJob, workers*2)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				hk := hostKey(job.target)
				jobGate := gate
				for _, tag := range strings.Split(job.tmpl.Info.Tags, ",") {
					if strings.EqualFold(strings.TrimSpace(tag), "ssh") {
						jobGate = sshGate
						break
					}
				}
				if err := jobGate.Acquire(ctx, hk); err != nil {
					report()
					continue
				}
				ec := execContext{responseCache: responseCache, client: client, rateTick: rateTick, retries: retries, timeout: timeout, collab: collab, allowCodeExec: p.AllowCodeExec, allowExploit: p.AllowExploit}
				fs, es := e.execTemplate(ctx, job.tmpl, job.target, ec)
				if len(job.tmpl.Workflows) > 0 {
					wfs, wes := e.execWorkflow(ctx, job.tmpl.Workflows, job.target, ec, 0)
					fs = append(fs, wfs...)
					es = append(es, wes...)
				}
				jobGate.Release(hk, errorsOverloaded(es))
				mu.Lock()
				for _, f := range fs {
					if e.store != nil {
						if er := e.store.SaveFinding(ctx, runID, f); er != nil {
							result.Errors = append(result.Errors, er.Error())
						}
					}
					result.Findings = append(result.Findings, f)
				}
				for _, e2 := range es {
					// Overload noise (port exhaustion / resets) is handled by the
					// host gate; keep a short sample so the log is not flooded.
					if isOverloadErr(e2) {
						continue
					}
					result.Errors = append(result.Errors, e2.Error())
				}
				mu.Unlock()
				report()
			}
		}()
	}
	enqueue := func(target string, t domain.Template) bool {
		select {
		case <-ctx.Done():
			return false
		case jobs <- scanJob{target: target, tmpl: t}:
			return true
		}
	}
feed:
	for _, target := range targets {
		for _, t := range templates {
			if err := template.Validate(t); err != nil {
				result.Errors = append(result.Errors, t.ID+": "+err.Error())
				continue
			}
			if ipOnly && skipTemplateOnIPTarget(t) {
				continue
			}
			if !databaseTemplateMatches(t, target, p.Services) {
				continue
			}
			if !enqueue(target, t) {
				break feed
			}
		}
	}
	close(jobs)
	wg.Wait()
	result.HTTPRequestsSaved = responseCache.hits
	if ctx.Err() != nil {
		status = "cancelled"
	}
	if err := e.store.FinishRun(ctx, runID, status); err != nil {
		return result, err
	}
	return result, nil
}

// newScanHTTPClient builds a shared client whose transport caps concurrent
// dials per host — the main defense against ephemeral-port exhaustion.
func newScanHTTPClient(timeoutSec, maxConnsPerHost int) *http.Client {
	if maxConnsPerHost < 1 {
		maxConnsPerHost = 1
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          maxConnsPerHost * 4,
		MaxIdleConnsPerHost:   maxConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// normalizeTarget puts target in the same "scheme://host[:port]" (no
// trailing slash) form resolveURL and buildHTTPRequest both build their
// literal prefix-matches against.
func normalizeTarget(target string) string {
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	return target
}

func resolveURL(target, p string) (string, error) {
	target = normalizeTarget(target)
	base, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	port := base.Port()
	if port == "" {
		if base.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	original := p
	if strings.Contains(original, "{{BaseURL}}") || strings.Contains(original, "{{RootURL}}") {
		p = strings.ReplaceAll(strings.ReplaceAll(p, "{{BaseURL}}", target), "{{RootURL}}", target)
	} else if strings.HasPrefix(original, "{{Hostname}}") || strings.HasPrefix(original, "{{Host}}") {
		if strings.HasPrefix(original, "{{Hostname}}") {
			p = target + strings.TrimPrefix(original, "{{Hostname}}")
		} else {
			p = target + strings.TrimPrefix(original, "{{Host}}")
		}
	} else {
		// Nuclei convention: Host = hostname without port, Hostname = host:port.
		values := map[string]string{"{{Host}}": base.Hostname(), "{{Hostname}}": base.Host, "{{Scheme}}": base.Scheme, "{{Port}}": port, "{{Path}}": base.Path}
		for token, value := range values {
			p = strings.ReplaceAll(p, token, value)
		}
	}
	if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
		if strings.HasPrefix(p, "/") {
			p = target + p
		} else {
			p = target + "/" + p
		}
	}
	p = rewritePortOverride(p)
	u, err := url.Parse(p)
	if err != nil {
		var escErr url.EscapeError
		if errors.As(err, &escErr) && (p == target || strings.HasPrefix(p, target+"/")) {
			// Deliberately malformed percent-encoding that a real HTTP server
			// accepts raw off the wire but Go's net/url refuses to even
			// parse: IIS-style "%u002e", a truncated "%A/" escape, a bare
			// '%' meant literally (laravel-debug-error.yaml,
			// CVE-2021-34429.yaml, CVE-2023-32235.yaml). Host/port are
			// already pinned here by the literal target+"/" prefix (p was
			// built by prepending target above), so there's nothing left for
			// url.Parse's checks below to add — hand the literal bytes to
			// execHTTPRequest's buildHTTPRequest, which sends them verbatim
			// via url.URL.Opaque instead of trying to parse them.
			return p, nil
		}
		return "", fmt.Errorf("invalid HTTP URL %q", p)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid HTTP URL %q", p)
	}
	if !strings.EqualFold(u.Hostname(), base.Hostname()) {
		return "", fmt.Errorf("template attempted to leave target host (%s)", u.Host)
	}
	// Pin to the port of the scan target. Selecting :8080 means web checks
	// still run — on 8080. Templates that rewrite to another port (e.g.
	// {{BaseURL}}:43800) are out of this service's scope.
	if effectiveHTTPPort(u) != effectiveHTTPPort(base) {
		return "", fmt.Errorf("template attempted to leave target port (%s -> %s)", base.Host, u.Host)
	}
	return u.String(), nil
}

// buildHTTPRequest builds the *http.Request for u (a URL string produced by
// resolveURL) exactly as http.NewRequestWithContext would — except when u
// carries bytes net/url refuses to parse (resolveURL's EscapeError fallback
// above: IIS-style "%u002e", a truncated "%XX" escape, a bare '%' meant
// literally). Those are deliberate path-traversal/WAF-bypass payloads real
// HTTP servers accept raw off the wire; only Go's own URL parser rejects
// them. In that case the request is built manually with URL.Opaque set to
// the literal request-target bytes — url.URL.RequestURI() returns Opaque
// unmodified (so long as it doesn't start with "//"), bypassing validation
// entirely while still using the same net/http client/transport for
// everything else (TLS, keep-alive, redirects).
func buildHTTPRequest(ctx context.Context, method, target, u, body string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(body))
	if err == nil {
		return req, nil
	}
	var escErr url.EscapeError
	if !errors.As(err, &escErr) {
		return nil, err
	}
	target = normalizeTarget(target)
	base, berr := url.Parse(target)
	if berr != nil {
		return nil, err
	}
	requestTarget := strings.TrimPrefix(u, target)
	if requestTarget == "" {
		requestTarget = "/"
	}
	req = (&http.Request{
		Method: method,
		URL:    &url.URL{Scheme: base.Scheme, Host: base.Host, Opaque: requestTarget},
		Host:   base.Host,
		Header: make(http.Header),
		Body:   io.NopCloser(strings.NewReader(body)),
	}).WithContext(ctx)
	if body != "" {
		req.ContentLength = int64(len(body))
	}
	return req, nil
}

// effectiveHTTPPort returns the explicit port, or the scheme default (80/443).
func effectiveHTTPPort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// rewritePortOverride handles nuclei's "{{BaseURL}}:8080/path" pattern: when an
// alternate port is appended after a BaseURL that already contains a port,
// keep the trailing (override) port.
var doublePortRE = regexp.MustCompile(`^(https?://)(\[[^\]]+\]|[^/\[\]:]+)(:\d+)(:\d+)(/.*)?$`)

func rewritePortOverride(raw string) string {
	if m := doublePortRE.FindStringSubmatch(raw); m != nil {
		return m[1] + m[2] + m[4] + m[5]
	}
	return raw
}

// rewriteSSLAddress collapses "host:port:port" (from "{{Host}}:{{Port}}" when
// Host already carried a port) into a single host:port pair.
var sslDoublePortRE = regexp.MustCompile(`^(\[[^\]]+\]|[^:]+)(:\d+)(:\d+)$`)

func rewriteSSLAddress(addr string) string {
	if m := sslDoublePortRE.FindStringSubmatch(addr); m != nil {
		return m[1] + m[3]
	}
	return addr
}

// buildEnv constructs the variable set a dsl matcher/extractor evaluates
// against, mirroring the common Nuclei response variables.
func buildEnv(status int, headers http.Header, body []byte) map[string]any {
	headerStr := headersToString(headers)
	env := map[string]any{
		"status_code":    float64(status),
		"content_length": float64(len(body)),
		"body":           string(body),
		"header":         headerStr,
		"all_headers":    headerStr,
		"response":       headerStr + "\n" + string(body),
		"content_type":   headers.Get("Content-Type"),
		"duration":       float64(0),
	}
	return env
}

// runExtractors evaluates a request's extractors, exposing every extracted
// value as a variable in env (so later dsl matchers can reference it) and
// returning a human-readable evidence string for the non-internal ones.
func runExtractors(extractors []domain.Extractor, env map[string]any, vars map[string]any, headers http.Header, body []byte) string {
	var evidence []string
	for _, ex := range extractors {
		var hay string
		switch strings.ToLower(ex.Part) {
		case "header":
			hay = headersToString(headers)
		case "all", "response":
			hay = headersToString(headers) + "\n" + string(body)
		default:
			if v, ok := env[strings.ToLower(ex.Part)].(string); ok && ex.Part != "" {
				hay = v
			} else {
				hay = string(body)
			}
		}
		var values []string
		switch strings.ToLower(ex.Type) {
		case "regex":
			for _, pattern := range ex.Regex {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				for _, m := range re.FindAllStringSubmatch(hay, -1) {
					group := ex.Group
					if group < 0 || group >= len(m) {
						group = 0
					}
					values = append(values, m[group])
				}
			}
		case "kval":
			for _, key := range ex.KVal {
				if v := headers.Get(key); v != "" {
					values = append(values, v)
				} else if v := headers.Get(strings.ReplaceAll(key, "_", "-")); v != "" {
					values = append(values, v)
				}
			}
		case "dsl":
			for _, expr := range ex.DSL {
				// Nuclei allows "tls_version, cipher" as a shorthand to pull
				// named env values rather than evaluate an expression.
				if vals := dslEnvNames(expr, env); len(vals) > 0 {
					values = append(values, vals...)
					continue
				}
				if v, err := dsl.Eval(expr, env); err == nil {
					if s := fmt.Sprintf("%v", v); s != "" {
						values = append(values, s)
					}
				}
			}
		case "xpath":
			for _, expr := range ex.XPath {
				values = append(values, xpathQuery(hay, expr, ex.Attribute)...)
			}
		case "json":
			// Evaluate each jq path against the JSON response body; if the body is
			// not JSON (e.g. ssl certificate checks), fall back to a top-level env
			// lookup of the field name.
			var doc any
			jsonOK := json.Unmarshal(body, &doc) == nil
			for _, path := range ex.JSON {
				if jsonOK {
					values = append(values, jqEval(doc, path)...)
				} else if key := strings.TrimPrefix(strings.TrimSpace(path), "."); key != "" {
					if v, ok := env[key].(string); ok && v != "" {
						values = append(values, v)
					}
				}
			}
		}
		if len(values) == 0 {
			continue
		}
		if ex.Name != "" {
			env[ex.Name] = values[0]
			// Propagate into the shared template vars so later requests /
			// flow steps can interpolate {{name}} and iterate(template.name).
			if vars != nil {
				if len(values) == 1 {
					vars[ex.Name] = values[0]
				} else {
					vars[ex.Name] = append([]string(nil), values...)
				}
			}
		}
		if !ex.Internal {
			label := ex.Name
			if label == "" {
				label = ex.Type
			}
			evidence = append(evidence, label+": "+strings.Join(values, ", "))
		}
	}
	return strings.Join(evidence, "; ")
}

// matchOrExtract decides whether a request produced a finding. With matchers,
// behaviour matches Nuclei: matchers must pass, and non-internal extractor
// output is appended as evidence. Without matchers, a successful non-internal
// extraction alone is enough (token/tech detector templates).
func matchOrExtract(ms []domain.Matcher, condition string, status int, headers http.Header, body []byte, env map[string]any, extractEvidence string) (bool, string) {
	if len(ms) == 0 {
		if extractEvidence == "" {
			return false, ""
		}
		return true, extractEvidence
	}
	matched, evidence := match(ms, condition, status, headers, body, env)
	if !matched {
		return false, ""
	}
	if extractEvidence != "" {
		if evidence != "" {
			evidence += "; "
		}
		evidence += extractEvidence
	}
	return true, evidence
}

func match(ms []domain.Matcher, condition string, status int, headers http.Header, body []byte, env map[string]any) (bool, string) {
	if len(ms) == 0 {
		return false, ""
	}
	results := make([]bool, 0, len(ms))
	evidence := ""
	for _, m := range ms {
		part := strings.ToLower(m.Part)
		var hay string
		switch {
		case isOOBPart(part):
			// Match against the out-of-band interaction our collaborator recorded
			// (exposed in env). Without a callback the value is empty, so the
			// matcher is false — it never falls through to the response body, which
			// would fabricate a match on a word like "http".
			hay = oobHay(part, env)
		case part == "header":
			hay = headersToString(headers)
		case part == "all":
			hay = headersToString(headers) + "\n" + string(body)
		default:
			// A named part (dns "answer", tcp "data", ssl "issuer_dn", ...) is read
			// from env when present; otherwise fall back to the response body.
			if v, ok := env[part].(string); ok && part != "" {
				hay = v
			} else {
				hay = string(body)
			}
		}
		if m.CaseInsensitive {
			hay = strings.ToLower(hay)
		}
		ok := false
		switch strings.ToLower(m.Type) {
		case "status":
			for _, n := range m.Status {
				if status == n {
					ok = true
					evidence = fmt.Sprintf("HTTP status %d", status)
					break
				}
			}
		case "size":
			for _, n := range m.Size {
				if len(body) == n {
					ok = true
					evidence = fmt.Sprintf("response size %d", n)
					break
				}
			}
		case "dsl":
			checks := make([]bool, 0, len(m.DSL))
			for _, expr := range m.DSL {
				v, err := dsl.EvalBool(expr, env)
				checks = append(checks, err == nil && v)
			}
			cond := m.Condition
			if cond == "" {
				cond = "or"
			}
			ok = combine(checks, cond)
			if ok && len(m.DSL) > 0 {
				// "dsl matched" alone tells a reviewer nothing; name the
				// condition(s) that actually fired (not the whole list for an
				// "or" match, which would wrongly imply every expression
				// passed).
				evidence = "dsl matched: " + strings.Join(passedExprs(m.DSL, checks), " && ")
			}
		case "xpath":
			checks := make([]bool, 0, len(m.XPath))
			for _, expr := range m.XPath {
				checks = append(checks, len(xpathQuery(hay, expr, "")) > 0)
			}
			cond := m.Condition
			if cond == "" {
				cond = "or"
			}
			ok = combine(checks, cond)
			if ok {
				evidence = "xpath matched: " + strings.Join(passedExprs(m.XPath, checks), " && ")
			}
		case "word":
			checks := make([]bool, 0, len(m.Words))
			for _, w := range m.Words {
				needle := w
				if m.CaseInsensitive {
					needle = strings.ToLower(needle)
				}
				checks = append(checks, strings.Contains(hay, needle))
			}
			condition := m.Condition
			if condition == "" {
				condition = "or"
			}
			ok = combine(checks, condition)
			if ok && len(m.Words) > 0 {
				evidence = "matched word: " + m.Words[0]
			}
		case "regex":
			checks := make([]bool, 0, len(m.Regex))
			for _, pattern := range m.Regex {
				re, err := regexp.Compile(pattern)
				checks = append(checks, err == nil && re.MatchString(hay))
			}
			condition := m.Condition
			if condition == "" {
				condition = "or"
			}
			ok = combine(checks, condition)
			if ok && len(m.Regex) > 0 {
				evidence = "matched regex"
			}
		case "binary":
			// Binary needles are hex-encoded; match them against the raw response
			// bytes (hay holds the body as a byte string).
			checks := make([]bool, 0, len(m.Binary))
			for _, h := range m.Binary {
				decoded, err := hex.DecodeString(strings.TrimSpace(h))
				checks = append(checks, err == nil && strings.Contains(hay, string(decoded)))
			}
			condition := m.Condition
			if condition == "" {
				condition = "or"
			}
			ok = combine(checks, condition)
			if ok && len(m.Binary) > 0 {
				evidence = "matched binary"
			}
		}
		if m.Negative {
			ok = !ok
		}
		results = append(results, ok)
	}
	return combine(results, condition), evidence
}

// dslEnvNames treats "a, b, c" as a list of env keys to extract (Nuclei
// shorthand used by ssl templates). Returns nil when the expression is not
// that form so the caller falls through to Eval.
func dslEnvNames(expr string, env map[string]any) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" || strings.ContainsAny(expr, "()=<>!&|") {
		return nil
	}
	parts := strings.Split(expr, ",")
	if len(parts) < 2 {
		return nil
	}
	var out []string
	for _, p := range parts {
		name := strings.TrimSpace(p)
		if name == "" {
			return nil
		}
		for _, r := range name {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
				return nil
			}
		}
		if v, ok := env[name]; ok {
			if s := fmt.Sprintf("%v", v); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// oastTimeout bounds how long a request waits for an out-of-band callback after
// sending its payload.
const oastTimeout = 8 * time.Second

// placeholderRE matches a {{...}} expression in a template string.
var placeholderRE = regexp.MustCompile(`\{\{([^{}]+)\}\}`)

// requestPlaceholders are substituted later from the target (resolveURL) or the
// OAST layer, so render leaves them untouched.
var requestPlaceholders = map[string]bool{
	"BaseURL": true, "RootURL": true, "Hostname": true, "Host": true,
	"Scheme": true, "Port": true, "Path": true, "interactsh-url": true,
}

// render evaluates every {{expr}} in s against env (template variables and
// generator functions such as rand_base/md5/base64), leaving request-level and
// OAST placeholders intact. {{randstr}} / {{randstr_N}} get a random value that
// is cached in env so repeated references in one template stay consistent.
func render(s string, env map[string]any) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
		inner := strings.TrimSpace(m[2 : len(m)-2])
		if requestPlaceholders[inner] {
			return m
		}
		if strings.HasPrefix(inner, "randstr") {
			if v, ok := env[inner]; ok {
				return fmt.Sprintf("%v", v)
			}
			r := randToken()
			env[inner] = r
			return r
		}
		v, err := dsl.Eval(inner, env)
		if err != nil {
			return m
		}
		return fmt.Sprintf("%v", v)
	})
}

func randToken() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 27)
	for i := range b {
		b[i] = chars[mathrand.Intn(len(chars))]
	}
	return string(b)
}

// evalVariables resolves a template's variables block in order (a later variable
// may reference an earlier one) into a fresh env the request rendering and dsl
// matchers then share.
func evalVariables(vars domain.VariableList) map[string]any {
	env := map[string]any{}
	for _, v := range vars {
		env[v.Name] = render(v.Value, env)
	}
	return env
}

// preparedRequest is one concrete HTTP request ready to send, built from either
// a structured path request or a raw request after variable substitution.
type preparedRequest struct {
	payload map[string]string
	method  string
	path    string // relative/absolute; target placeholders resolved by resolveURL
	body    string
	headers map[string]string
	timeout time.Duration // from @timeout annotation; 0 = use scan default
	once    bool          // @once: emit only for the first payload combo
	host    string        // @Host override (host, host:port, or URL)
	tlsSNI  string        // @tls-sni value (literal, request.host, interactsh-url)
}

// maxPayloadCombos caps how many payload combinations one request expands into,
// guarding against a clusterbomb product exploding.
const maxPayloadCombos = 5000

// prepareRequests expands one template request definition into concrete requests,
// substituting template variables, payloads (fuzzing) and target placeholders. A
// `raw:` block is parsed into method/path/headers/body; otherwise each `path`
// entry is used.
func prepareRequests(r domain.HTTPRequest, vars map[string]any, tvars map[string]string, libraryDir, source string) ([]preparedRequest, []error) {
	combos, errs := payloadCombos(r, vars, tvars, libraryDir, source)
	var out []preparedRequest
	onceEmitted := map[int]bool{}
	for _, combo := range combos {
		env := vars
		if len(combo) > 0 {
			env = make(map[string]any, len(vars)+len(combo))
			for k, v := range vars {
				env[k] = v
			}
			for k, v := range combo {
				env[k] = v
			}
		}
		if len(r.Raw) > 0 {
			for i, raw := range r.Raw {
				pr, err := parseRaw(applyTargetVars(render(raw, env), tvars))
				if err != nil {
					errs = append(errs, err)
					continue
				}
				if pr.once {
					if onceEmitted[i] {
						continue
					}
					onceEmitted[i] = true
				}
				pr.payload = combo
				out = append(out, pr)
			}
			continue
		}
		method := strings.ToUpper(r.Method)
		if method == "" {
			method = "GET"
		}
		body := applyTargetVars(render(r.Body, env), tvars)
		headers := renderHeaders(r.Headers, env, tvars)
		for _, p := range r.Path {
			// Path keeps target placeholders ({{BaseURL}} etc.) for resolveURL.
			out = append(out, preparedRequest{method: method, path: render(p, env), body: body, headers: headers, payload: combo})
		}
	}
	return out, errs
}

// payloadCombos resolves a request's payloads into attack-mode combinations. With
// no payloads it returns a single empty combination. Payload values are rendered
// (so entries like {{FQDN}} or {{date_time('%Y')}} resolve), and file payloads
// are read from the template library.
func payloadCombos(r domain.HTTPRequest, vars map[string]any, tvars map[string]string, libraryDir, source string) ([]map[string]string, []error) {
	if len(r.Payloads) == 0 {
		return []map[string]string{{}}, nil
	}
	names := make([]string, 0, len(r.Payloads))
	for name := range r.Payloads {
		names = append(names, name)
	}
	sort.Strings(names)
	lists := make([][]string, len(names))
	var errs []error
	for i, name := range names {
		p := r.Payloads[name]
		var values []string
		if p.File != "" {
			lines, err := readPayloadFile(libraryDir, source, p.File)
			if err != nil {
				errs = append(errs, fmt.Errorf("payload %q: %w", name, err))
				return nil, errs // cannot run the request without its payload set
			}
			values = lines
		} else {
			values = p.Values
		}
		rendered := make([]string, 0, len(values))
		for _, v := range values {
			rendered = append(rendered, applyTargetVars(render(v, vars), tvars))
		}
		if len(rendered) == 0 {
			return nil, errs
		}
		lists[i] = rendered
	}
	return buildCombos(names, lists, strings.ToLower(r.Attack)), errs
}

// buildCombos combines payload lists per attack mode: clusterbomb is the
// cartesian product; pitchfork and batteringram iterate the lists in parallel by
// index. The result is capped by maxPayloadCombos.
func buildCombos(names []string, lists [][]string, attack string) []map[string]string {
	if attack == "clusterbomb" {
		combos := []map[string]string{{}}
		for i, name := range names {
			var next []map[string]string
			for _, c := range combos {
				for _, val := range lists[i] {
					m := make(map[string]string, len(c)+1)
					for k, v := range c {
						m[k] = v
					}
					m[name] = val
					next = append(next, m)
					if len(next) >= maxPayloadCombos {
						return next
					}
				}
			}
			combos = next
		}
		return combos
	}
	// pitchfork / batteringram: parallel by index, bounded by the shortest list.
	n := 0
	for i, l := range lists {
		if i == 0 || len(l) < n {
			n = len(l)
		}
	}
	if n > maxPayloadCombos {
		n = maxPayloadCombos
	}
	combos := make([]map[string]string, 0, n)
	for i := 0; i < n; i++ {
		m := make(map[string]string, len(names))
		for j, name := range names {
			m[name] = lists[j][i]
		}
		combos = append(combos, m)
	}
	if len(combos) == 0 {
		return []map[string]string{{}}
	}
	return combos
}

// readPayloadFile loads a wordlist referenced by a payload, resolved relative to
// the template's directory or the nuclei-templates root.
func readPayloadFile(libraryDir, source, file string) ([]string, error) {
	candidates := []string{
		filepath.Join(libsync.TemplateDir(libraryDir), filepath.Dir(source), file),
		filepath.Join(libsync.TemplateDir(libraryDir), file),
		file,
	}
	for _, c := range candidates {
		data, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		var out []string
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimRight(line, "\r"); strings.TrimSpace(line) != "" {
				out = append(out, line)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("payload file not found: %s", file)
}

// parseRaw turns a raw HTTP request (request line, headers, blank line, body)
// into a preparedRequest. Leading nuclei annotations (@timeout, @once, @Host,
// @tls-sni) are peeled off before the request line. The Host header is dropped:
// net/http derives it from the resolved target URL (unless @Host overrides).
func parseRaw(raw string) (preparedRequest, error) {
	raw = strings.TrimLeft(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	head, body, _ := strings.Cut(raw, "\n\n")
	lines := strings.Split(head, "\n")
	pr := preparedRequest{headers: map[string]string{}}
	i := 0
	for ; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "@") {
			break
		}
		applyRawAnnotation(line, &pr)
	}
	if i >= len(lines) {
		return preparedRequest{}, fmt.Errorf("invalid raw request line: %q", strings.TrimSpace(lines[0]))
	}
	fields := strings.Fields(lines[i])
	// "GET HTTP/1.1" (no path) — used by some SNI probes; treat path as "/".
	if len(fields) == 2 && strings.HasPrefix(strings.ToUpper(fields[1]), "HTTP/") {
		fields = []string{fields[0], "/", fields[1]}
	}
	if len(fields) < 2 {
		return preparedRequest{}, fmt.Errorf("invalid raw request line: %q", strings.TrimSpace(lines[i]))
	}
	pr.method = strings.ToUpper(fields[0])
	pr.path = fields[1]
	for _, l := range lines[i+1:] {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			k = strings.TrimSpace(k)
			if k == "" || strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
				continue
			}
			pr.headers[k] = strings.TrimSpace(v)
		}
	}
	pr.body = body
	return pr, nil
}

const maxAnnotationTimeout = 5 * time.Minute

func applyRawAnnotation(line string, pr *preparedRequest) {
	lower := strings.ToLower(line)
	switch {
	case lower == "@once":
		pr.once = true
	case strings.HasPrefix(lower, "@timeout:"):
		val := strings.TrimSpace(line[len("@timeout:"):])
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			if d > maxAnnotationTimeout {
				d = maxAnnotationTimeout
			}
			pr.timeout = d
		}
	case strings.HasPrefix(lower, "@host:"):
		pr.host = strings.TrimSpace(line[len("@host:"):])
	case strings.HasPrefix(lower, "@tls-sni:"):
		pr.tlsSNI = strings.TrimSpace(line[len("@tls-sni:"):])
	}
}

// applyHostOverride rewrites the resolved URL's host (and optional scheme) from
// a nuclei @Host annotation. Same-host port changes stay in scope; off-host
// overrides are rejected by the caller.
func applyHostOverride(resolved, hostAnn string) (string, error) {
	u, err := url.Parse(resolved)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(hostAnn)
	switch {
	case strings.HasPrefix(strings.ToLower(value), "http://"):
		u.Scheme = "http"
		value = value[len("http://"):]
	case strings.HasPrefix(strings.ToLower(value), "https://"):
		u.Scheme = "https"
		value = value[len("https://"):]
	}
	value = strings.TrimSuffix(value, "/")
	if _, _, err := net.SplitHostPort(value); err == nil {
		u.Host = value
	} else if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(value, port)
	} else {
		u.Host = value
	}
	return u.String(), nil
}

func sameTargetHost(a, b string) bool {
	ha, errA := url.Parse(a)
	hb, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	if ha.Hostname() == "" || hb.Hostname() == "" {
		return strings.EqualFold(ha.Host, hb.Host)
	}
	return strings.EqualFold(ha.Hostname(), hb.Hostname())
}

// targetVars are the request-level placeholders derived from the scan target.
func targetVars(target string) map[string]string {
	t := strings.TrimRight(strings.TrimSpace(target), "/")
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	base, err := url.Parse(t)
	if err != nil {
		return map[string]string{}
	}
	port := base.Port()
	if port == "" {
		if base.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	host := base.Hostname()
	vars := map[string]string{
		"BaseURL": t, "RootURL": t,
		// Match nuclei: Host = bare hostname, Hostname = host:port.
		"Host": host, "Hostname": base.Host,
		"Scheme": base.Scheme, "Port": port, "Path": base.Path,
		"FQDN": host,
	}
	// DNS-derived placeholders (empty for bare IPs).
	if net.ParseIP(host) == nil {
		labels := strings.Split(host, ".")
		if len(labels) >= 2 {
			vars["RDN"] = strings.Join(labels[len(labels)-2:], ".") // root domain: example.com
			vars["DN"] = labels[len(labels)-2]                      // domain name: example
			vars["TLD"] = labels[len(labels)-1]                     // com
			vars["SD"] = strings.Join(labels[:len(labels)-2], ".")  // subdomain: www
		}
	}
	return vars
}

func applyTargetVars(s string, tvars map[string]string) string {
	if len(tvars) == 0 || !strings.Contains(s, "{{") {
		return s
	}
	for k, v := range tvars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func renderHeaders(h map[string]string, vars map[string]any, tvars map[string]string) map[string]string {
	if len(h) == 0 {
		return h
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[applyTargetVars(render(k, vars), tvars)] = applyTargetVars(render(v, vars), tvars)
	}
	return out
}

// isOOBPart reports whether a matcher part refers to an out-of-band
// (interactsh/OAST) interaction. Nuclei exposes these as interactsh_protocol,
// interactsh_request and interactsh_response.
func isOOBPart(part string) bool {
	return strings.HasPrefix(part, "interactsh") || part == "oob"
}

// oobHay returns the recorded out-of-band interaction value a matcher part
// refers to, read from env (populated after a collaborator callback). An absent
// value yields "" so the matcher does not match.
func oobHay(part string, env map[string]any) string {
	key := "interactsh_protocol"
	switch {
	case strings.Contains(part, "request"):
		key = "interactsh_request"
	case strings.Contains(part, "response"):
		key = "interactsh_response"
	}
	if v, ok := env[key].(string); ok {
		return v
	}
	return ""
}

// usesInteractsh reports whether a request embeds the out-of-band callback
// placeholder in anything it sends.
func usesInteractsh(path, body string, headers map[string]string) bool {
	if strings.Contains(path, oast.Placeholder) || strings.Contains(body, oast.Placeholder) {
		return true
	}
	for k, v := range headers {
		if strings.Contains(k, oast.Placeholder) || strings.Contains(v, oast.Placeholder) {
			return true
		}
	}
	return false
}

// substituteHeaders returns a copy of headers with every placeholder occurrence
// (in keys and values) replaced, leaving the template's map untouched.
func substituteHeaders(headers map[string]string, placeholder, value string) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[strings.ReplaceAll(k, placeholder, value)] = strings.ReplaceAll(v, placeholder, value)
	}
	return out
}

func combine(xs []bool, condition string) bool {
	if len(xs) == 0 {
		return false
	}
	if strings.EqualFold(condition, "or") {
		for _, v := range xs {
			if v {
				return true
			}
		}
		return false
	}
	for _, v := range xs {
		if !v {
			return false
		}
	}
	return true
}

// passedExprs returns the exprs whose matching check was true, preserving
// order — used so "dsl matched"/"xpath matched" evidence names the
// condition(s) that actually fired rather than a meaningless fixed string,
// without claiming every expression passed for an "or" match where only one
// did.
func passedExprs(exprs []string, checks []bool) []string {
	var out []string
	for i, c := range checks {
		if c && i < len(exprs) {
			out = append(out, exprs[i])
		}
	}
	return out
}

// convertServicesForJS adapts domain.Service (this package's model) to
// js.DiscoveredService (a local, dependency-light stand-in the js package
// uses to keep it free of a domain import) for discoveredPorts(...).
func convertServicesForJS(services []domain.Service) []js.DiscoveredService {
	out := make([]js.DiscoveredService, len(services))
	for i, s := range services {
		out[i] = js.DiscoveredService{Host: s.Host, Port: s.Port, Name: s.Name}
	}
	return out
}

func headersToString(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			// Real HTTP header lines are CRLF-terminated, and templates split
			// on that literally (e.g. cookies-without-secure.yaml's
			// javascript: step does content.split(/\r\n/) on
			// template.http_all_headers) — a bare \n here would silently
			// turn the whole header block into one unsplit line.
			b.WriteString("\r\n")
		}
	}
	return b.String()
}
