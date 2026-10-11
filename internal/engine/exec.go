package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"wscan/internal/domain"
	"wscan/internal/libsync"
	"wscan/internal/oast"
	"wscan/internal/template"
)

// execContext carries the per-scan knobs the executors need.
type execContext struct {
	client        *http.Client
	rateTick      <-chan time.Time
	retries       int
	timeout       int
	collab        *oast.Collaborator
	allowCodeExec bool
	allowExploit  bool
	cookieJar     http.CookieJar
	responseCache *httpResponseCache
}

// execTemplate runs one template's requests (HTTP, TCP/network, DNS, SSL) against
// a target and returns the findings and errors. It does not save to the store;
// the caller persists the results. This is shared by the main scan loop and the
// workflow executor. A template with a flow: script is dispatched to execFlow
// instead, which decides which request blocks to run via the embedded JS engine.
func (e *Engine) execTemplate(ctx context.Context, t domain.Template, target string, ec execContext) ([]domain.Finding, []error) {
	// Gate exploit-class templates before touching any protocol; they trigger
	// the target vulnerability instead of only detecting it.
	if t.IsExploit && !ec.allowExploit {
		return nil, []error{fmt.Errorf("%s: exploit: check is disabled for this project — enable it in settings (and acknowledge the warning) to run exploit checks", t.ID)}
	}
	if ec.responseCache != nil && !cacheableTemplate(t) {
		end := ec.responseCache.beginChange(cacheHost(target))
		defer end()
	}
	// Session state belongs to this template and target, never another scan.
	ec.cookieJar, _ = cookiejar.New(nil)
	vars := evalVariables(t.Variables)
	tvars := targetVars(target)
	if t.Flow != "" {
		return e.execFlow(ctx, t, target, vars, tvars, ec)
	}
	var findings []domain.Finding
	var errs []error
	for _, reqDef := range t.HTTP {
		fs, es, _ := e.execHTTPRequest(ctx, t, reqDef, target, vars, tvars, ec)
		findings = append(findings, fs...)
		errs = append(errs, es...)
		if ctx.Err() != nil {
			return findings, errs
		}
	}
	d := time.Duration(ec.timeout) * time.Second
	for _, req := range append(append([]domain.TCPRequest{}, t.TCP...), t.Network...) {
		fs, es := runTCP(ctx, t, req, target, vars, tvars, d)
		findings = append(findings, fs...)
		errs = append(errs, es...)
	}
	for _, req := range t.DNS {
		fs, es := runDNS(ctx, t, req, vars, tvars, d)
		findings = append(findings, fs...)
		errs = append(errs, es...)
	}
	for _, req := range t.SSL {
		fs, es := runSSL(ctx, t, req, target, vars, tvars, d)
		findings = append(findings, fs...)
		errs = append(errs, es...)
	}
	for _, req := range t.Code {
		fs, es := execCode(ctx, t, req, target, vars, tvars, ec.allowCodeExec, d)
		findings = append(findings, fs...)
		errs = append(errs, es...)
	}
	for _, req := range t.JavaScript {
		fs, es, _ := execJavaScript(ctx, t, req, target, vars, tvars, e.config.LibraryDir, d)
		findings = append(findings, fs...)
		errs = append(errs, es...)
	}
	return findings, errs
}

// execHTTPRequest runs one http: request block (which may expand into several
// prepared requests via payloads/attack fuzzing) against target. Factored out
// of execTemplate so execFlow can also call a single indexed http block.
// last, when non-nil, receives a snapshot of the final response (for flow
// scripts that read http(N).body / http_last_response).
func (e *Engine) execHTTPRequest(ctx context.Context, t domain.Template, reqDef domain.HTTPRequest, target string, vars map[string]any, tvars map[string]string, ec execContext) (findings []domain.Finding, errs []error, last *httpRespSnap) {
	if ec.cookieJar == nil {
		ec.cookieJar, _ = cookiejar.New(nil)
	}
	resolutionTarget := target
	if reqDef.DisablePathAutomerge {
		if origin, err := url.Parse(normalizeTarget(target)); err == nil {
			origin.Path, origin.RawPath, origin.RawQuery, origin.Fragment = "", "", "", ""
			resolutionTarget = origin.String()
		}
	}
	preps, prepErrs := prepareRequests(reqDef, vars, tvars, e.config.LibraryDir, t.Source)
	for _, pe := range prepErrs {
		errs = append(errs, pe)
	}
	for _, pr := range preps {
		reqPath, reqBody, reqHeaders := pr.path, pr.body, pr.headers
		var oastToken string
		if ec.collab != nil && (usesInteractsh(pr.path, pr.body, pr.headers) || strings.EqualFold(pr.tlsSNI, "interactsh-url")) {
			tok, oobURL := ec.collab.NewURL()
			oastToken = tok
			reqPath = strings.ReplaceAll(reqPath, oast.Placeholder, oobURL)
			reqBody = strings.ReplaceAll(reqBody, oast.Placeholder, oobURL)
			reqHeaders = substituteHeaders(reqHeaders, oast.Placeholder, oobURL)
			if strings.EqualFold(pr.tlsSNI, "interactsh-url") {
				if u, err := url.Parse(oobURL); err == nil && u.Hostname() != "" {
					pr.tlsSNI = u.Hostname()
				} else {
					pr.tlsSNI = strings.TrimPrefix(strings.TrimPrefix(oobURL, "https://"), "http://")
				}
			}
		}
		u, err := resolveURL(resolutionTarget, reqPath)
		if err != nil {
			errs = append(errs, templateErr(t.ID, err))
			continue
		}
		if pr.host != "" {
			overridden, herr := applyHostOverride(u, pr.host)
			if herr != nil {
				errs = append(errs, templateErr(t.ID, herr))
				continue
			}
			// Off-host @Host (token checks, self-contained) is out of scope —
			// skip quietly instead of flooding the scan log. Same-host port
			// changes are also out of scope when the scan is pinned to one
			// service port (see resolveURL).
			if !sameTargetHost(overridden, target) {
				continue
			}
			if ou, e1 := url.Parse(overridden); e1 == nil {
				if tu, e2 := url.Parse(target); e2 == nil && effectiveHTTPPort(ou) != effectiveHTTPPort(tu) {
					continue
				}
			}
			u = overridden
		}
		client := requestHTTPClient(ec.client, reqDef, target, ec.cookieJar)
		reqTimeout := time.Duration(ec.timeout) * time.Second
		if pr.timeout > 0 {
			reqTimeout = pr.timeout
			c := *client
			c.Timeout = reqTimeout + time.Second
			client = &c
		}
		if pr.tlsSNI != "" && !strings.EqualFold(pr.tlsSNI, "interactsh-url") {
			sni := pr.tlsSNI
			if strings.EqualFold(sni, "request.host") {
				if parsed, perr := url.Parse(u); perr == nil {
					sni = parsed.Hostname()
				}
			}
			client = clientWithSNI(client, sni, reqTimeout)
		}
		limit := int64(1 << 20)
		if reqDef.MaxSize > 0 {
			limit = reqDef.MaxSize
		}
		build := func(requestCtx context.Context) (*http.Request, error) {
			req, err := buildHTTPRequest(requestCtx, pr.method, resolutionTarget, u, reqBody)
			if err != nil {
				return nil, err
			}
			for k, v := range reqHeaders {
				if httpguts.ValidHeaderFieldName(k) && httpguts.ValidHeaderFieldValue(v) {
					req.Header.Set(k, v)
				}
			}
			return req, nil
		}
		load := func() (httpResponseData, error) { return fetchHTTPResponse(ctx, client, ec, reqTimeout, limit, build) }
		var data httpResponseData
		request, buildErr := build(ctx)
		if buildErr != nil {
			errs = append(errs, templateErr(t.ID, buildErr))
			continue
		}
		key, eligible := httpResponseCacheKey(request, reqDef, reqTimeout, limit)
		if ec.responseCache != nil && cacheableTemplate(t) && eligible && pr.tlsSNI == "" && oastToken == "" {
			data, err = ec.responseCache.get(ctx, cacheHost(u), key, t.ID, load)
		} else {
			if ec.responseCache != nil && cacheableTemplate(t) {
				end := ec.responseCache.beginChange(cacheHost(u))
				data, err = load()
				end()
			} else {
				data, err = load()
			}
		}
		if ctx.Err() != nil {
			return findings, errs, last
		}
		if err != nil {
			errs = append(errs, templateErr(t.ID+" "+target, err))
			continue
		}
		body, header, elapsed := data.body, data.header, data.elapsed
		env := buildEnv(data.status, header, body)
		env["duration"] = elapsed.Seconds()
		for k, v := range pr.payload {
			if _, exists := env[k]; !exists {
				env[k] = v
			}
		}
		for k, v := range vars {
			if _, ok := env[k]; !ok {
				env[k] = v
			}
		}
		if oastToken != "" {
			if hits := ec.collab.Poll(ctx, oastToken, oastTimeout); len(hits) > 0 {
				env["interactsh_protocol"] = hits[0].Protocol
				env["interactsh_request"] = hits[0].Request
				env["interactsh_response"] = ""
			}
		}
		extractEvidence := runExtractors(reqDef.Extractors, env, vars, header, body)
		matched, evidence := matchOrExtract(reqDef.Matchers, reqDef.MatchersCondition, data.status, header, body, env, extractEvidence)
		last = &httpRespSnap{
			// Matched = matchers passed (incl. internal-only gates). Flow uses
			// this for && / if; findings are still suppressed for internal-only.
			Matched:     matched,
			Body:        string(body),
			StatusCode:  data.status,
			Header:      env["header"].(string),
			ContentType: headersGet(header, "Content-Type"),
			URL:         u,
		}
		if !matched {
			continue
		}
		// Nuclei internal matchers gate later steps / feed extractors; they
		// must not emit findings on their own (same rule as tcp:/code:).
		if matchersOnlyInternal(reqDef.Matchers) {
			if reqDef.StopAtFirstMatch {
				return findings, errs, last
			}
			continue
		}
		findings = append(findings, domain.Finding{
			TemplateID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity,
			Target: target, MatchedAt: u, Evidence: evidence, Risk: t.Risk, Time: data.observedAt,
		})
		if reqDef.StopAtFirstMatch {
			return findings, errs, last
		}
	}
	return findings, errs, last
}

func headersGet(h http.Header, key string) string {
	if h == nil {
		return ""
	}
	return h.Get(key)
}

// httpRespSnap is the last HTTP response seen by a request block — exposed to
// flow scripts as http(N).body / http_last_response.
type httpRespSnap struct {
	Matched     bool
	Body        string
	StatusCode  int
	Header      string
	ContentType string
	URL         string
}

// clientWithSNI returns a shallow clone of c whose TLS handshake uses serverName.
func clientWithSNI(c *http.Client, serverName string, timeout time.Duration) *http.Client {
	clone := *c
	clone.Timeout = timeout + time.Second
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: true, ServerName: serverName}
	switch tr := base.(type) {
	case *http.Transport:
		t := tr.Clone()
		t.TLSClientConfig = tlsCfg
		// Keep per-host dial caps from the shared scan transport.
		clone.Transport = t
	default:
		clone.Transport = &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     tlsCfg,
			MaxConnsPerHost:     8,
			MaxIdleConnsPerHost: 8,
			DialContext:         (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		}
	}
	return &clone
}

const maxWorkflowDepth = 6

// execWorkflow runs workflow entries: each referenced template is executed, and
// when it matches, its subtemplates (and matcher-named subtemplates) run in turn.
// Tag-based entries are skipped (no tag index in the native engine).
func (e *Engine) execWorkflow(ctx context.Context, entries []domain.WorkflowEntry, target string, ec execContext, depth int) ([]domain.Finding, []error) {
	if depth >= maxWorkflowDepth {
		return nil, nil
	}
	if ec.responseCache != nil {
		end := ec.responseCache.beginChange(cacheHost(target))
		defer end()
	}
	var findings []domain.Finding
	var errs []error
	for _, entry := range entries {
		if entry.Template == "" {
			continue // tag-based selection is unsupported natively
		}
		ref, err := e.loadTemplate(entry.Template)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		fs, es := e.execTemplate(ctx, ref, target, ec)
		errs = append(errs, es...)
		findings = append(findings, fs...)
		if len(fs) == 0 {
			continue // no match: do not descend into subtemplates
		}
		sub := append([]domain.WorkflowEntry{}, entry.Subtemplates...)
		for _, m := range entry.Matchers {
			sub = append(sub, m.Subtemplates...)
		}
		if len(sub) > 0 {
			wf, we := e.execWorkflow(ctx, sub, target, ec, depth+1)
			findings = append(findings, wf...)
			errs = append(errs, we...)
		}
	}
	return findings, errs
}

// loadTemplate loads and natively parses a template referenced by a workflow,
// resolved under the template library.
func (e *Engine) loadTemplate(path string) (domain.Template, error) {
	clean := filepath.FromSlash(path)
	candidates := []string{
		filepath.Join(libsync.TemplateDir(e.config.LibraryDir), clean),
		filepath.Join(e.config.LibraryDir, clean),
	}
	for _, c := range candidates {
		data, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		return template.ForExecution(data, path)
	}
	return domain.Template{}, templateErr(path, os.ErrNotExist)
}

func templateErr(id string, err error) error {
	return &wrappedErr{id: id, err: err}
}

type wrappedErr struct {
	id  string
	err error
}

func (w *wrappedErr) Error() string { return w.id + ": " + w.err.Error() }
func (w *wrappedErr) Unwrap() error { return w.err }

// requestHTTPClient applies template options without changing the shared client.
// Redirects stay on the selected host and port even when redirects:true is set.
func requestHTTPClient(base *http.Client, request domain.HTTPRequest, target string, jar http.CookieJar) *http.Client {
	client := *base
	client.Jar = nil
	if request.CookieReuse && !request.DisableCookie {
		client.Jar = jar
	}
	maximum := request.MaxRedirects
	if maximum == 0 {
		maximum = 5
	}
	selected, _ := url.Parse(normalizeTarget(target))
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if !request.Redirects && !request.HostRedirects {
			return http.ErrUseLastResponse
		}
		// len(via)==1 is the first redirect, so max-redirects:1 permits one hop.
		if len(via) > maximum {
			return http.ErrUseLastResponse
		}
		if selected == nil || !strings.EqualFold(next.URL.Hostname(), selected.Hostname()) || effectiveHTTPPort(next.URL) != effectiveHTTPPort(selected) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return &client
}
