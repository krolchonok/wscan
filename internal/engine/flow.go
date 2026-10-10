package engine

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/dop251/goja"

	"wscan/internal/domain"
)

// flowScriptTimeout caps a flow: script's total run time — a safety net
// against a runaway script (e.g. an infinite JS loop), independent of ctx,
// which may carry no overall deadline of its own.
const flowScriptTimeout = 3 * time.Minute

const flowStopInterrupt = "flow stop"

// execFlow runs a template's flow: script (a one-liner like "http(1) &&
// http(2)" or a multi-line block) on the embedded goja JS engine. The script
// decides which http/tcp/network/dns/ssl request block — 1-indexed, in the
// order each appears under its YAML key — runs, and in what order, instead
// of execTemplate's default of running every block unconditionally.
//
// Named ids are also accepted: http("leak") resolves the http: block whose
// yaml `id:` is "leak" (nuclei flow style). Numeric args stay 1-based.
//
// http(N) returns a response object (with .body / .status_code / …) when
// matchers pass — truthy for && / if — or false when they miss. The last
// response (matched or not) is also exposed as http_last_response. stop()
// aborts the script without treating it as an error.
//
// The script only ever calls back into the same executors execTemplate uses
// (execHTTPRequest/runTCP/runDNS/runSSL) against this template's own request
// blocks: nothing is shelled out to an external interpreter or process, so
// this stays inside the "only our own engine" rule exactly like the embedded
// Lua VM already does for NSE.
//
// A script that also needs a code: block is still gated separately; javascript:
// blocks are executed natively via internal/engine/js.
func (e *Engine) execFlow(ctx context.Context, t domain.Template, target string, vars map[string]any, tvars map[string]string, ec execContext) ([]domain.Finding, []error) {
	var findings []domain.Finding
	var errs []error
	d := time.Duration(ec.timeout) * time.Second

	vm := goja.New()
	stopped := false

	// indicesOrAll turns the JS call's arguments into 1-based block indices:
	// no arguments (e.g. "http()") means "run every block of this type, in
	// order", matching nuclei's own flow semantics. A string argument looks
	// up the block by yaml id:; a number is 1-based.
	indicesOrAll := func(args []goja.Value, total int, resolveName func(string) int) []int {
		if len(args) == 0 {
			out := make([]int, total)
			for i := range out {
				out[i] = i + 1
			}
			return out
		}
		out := make([]int, 0, len(args))
		for _, a := range args {
			exported := a.Export()
			switch v := exported.(type) {
			case string:
				if n, err := strconv.Atoi(v); err == nil {
					out = append(out, n)
					continue
				}
				if resolveName != nil {
					if idx := resolveName(v); idx > 0 {
						out = append(out, idx)
						continue
					}
				}
				// Unknown name — surface as index 0 so the range check errors.
				out = append(out, 0)
			case int64:
				out = append(out, int(v))
			case int:
				out = append(out, v)
			case float64:
				out = append(out, int(v))
			default:
				out = append(out, int(a.ToInteger()))
			}
		}
		return out
	}

	httpByID := func(name string) int {
		for i, req := range t.HTTP {
			if req.ID == name {
				return i + 1
			}
		}
		return 0
	}

	snapToJS := func(snap *httpRespSnap) *goja.Object {
		obj := vm.NewObject()
		_ = obj.Set("body", snap.Body)
		_ = obj.Set("status_code", snap.StatusCode)
		_ = obj.Set("header", snap.Header)
		_ = obj.Set("all_headers", snap.Header)
		_ = obj.Set("headers", snap.Header)
		_ = obj.Set("content_type", snap.ContentType)
		_ = obj.Set("url", snap.URL)
		return obj
	}

	// register exposes fnName(...) for non-HTTP protocols: bool matched only.
	register := func(fnName string, total int, resolveName func(string) int, run func(idx int) ([]domain.Finding, []error)) {
		vm.Set(fnName, func(call goja.FunctionCall) goja.Value {
			matched := false
			for _, idx := range indicesOrAll(call.Arguments, total, resolveName) {
				if ctx.Err() != nil || stopped {
					return vm.ToValue(matched)
				}
				if idx < 1 || idx > total {
					// Matches real nuclei's own flow_internal.go requestExecutor:
					// an invalid/out-of-range request id is logged internally
					// (debug-only) and the call just returns false — it is not
					// surfaced to the user as a check error. Some upstream
					// templates genuinely reference a request id their own flow
					// doesn't define (see CVE-2026-3055.yaml's "http(1) ||
					// http(2)" against a single http: block whose own
					// stop-at-first-match already covers both alternatives).
					continue
				}
				fs, es := run(idx)
				errs = append(errs, es...)
				findings = append(findings, fs...)
				if len(fs) > 0 {
					matched = true
				}
			}
			return vm.ToValue(matched)
		})
	}

	// http(...) — returns a response object when matchers pass (truthy for
	// && / if / http(1).body), else false. Always updates http_last_response
	// when a response was received.
	vm.Set("http", func(call goja.FunctionCall) goja.Value {
		ret := vm.ToValue(false)
		for _, idx := range indicesOrAll(call.Arguments, len(t.HTTP), httpByID) {
			if ctx.Err() != nil || stopped {
				return ret
			}
			if idx < 1 || idx > len(t.HTTP) {
				// Silent, like register()'s generic case above — see its comment.
				ret = vm.ToValue(false)
				continue
			}
			fs, es, snap := e.execHTTPRequest(ctx, t, t.HTTP[idx-1], target, vars, tvars, ec)
			errs = append(errs, es...)
			findings = append(findings, fs...)
			if snap == nil {
				ret = vm.ToValue(false)
				continue
			}
			obj := snapToJS(snap)
			_ = vm.Set("http_last_response", obj)
			// Nuclei exposes the last response's fields as template.http_* —
			// e.g. cookies-without-secure.yaml reads template.http_all_headers
			// in its javascript() step to inspect Set-Cookie lines.
			vars["http_body"] = snap.Body
			vars["http_status_code"] = snap.StatusCode
			vars["http_header"] = snap.Header
			vars["http_all_headers"] = snap.Header
			vars["http_headers"] = snap.Header
			vars["http_content_type"] = snap.ContentType
			vars["http_url"] = snap.URL
			if snap.Matched {
				ret = obj
			} else {
				ret = vm.ToValue(false)
			}
		}
		return ret
	})

	register("tcp", len(t.TCP), nil, func(idx int) ([]domain.Finding, []error) {
		return runTCP(ctx, t, t.TCP[idx-1], target, vars, tvars, d)
	})
	register("network", len(t.Network), nil, func(idx int) ([]domain.Finding, []error) {
		return runTCP(ctx, t, t.Network[idx-1], target, vars, tvars, d)
	})
	register("dns", len(t.DNS), nil, func(idx int) ([]domain.Finding, []error) {
		return runDNS(ctx, t, t.DNS[idx-1], vars, tvars, d)
	})
	register("ssl", len(t.SSL), nil, func(idx int) ([]domain.Finding, []error) {
		return runSSL(ctx, t, t.SSL[idx-1], target, vars, tvars, d)
	})
	// javascript(...) — same register() contract (bool matched) as
	// tcp/network/dns/ssl, plus nuclei's {{javascript_response}} convention:
	// the last-run block's response becomes a template variable, readable by
	// a later http()/javascript() call in the same flow (e.g.
	// CVE-2022-24637's http(3) body embeds {{javascript_response}}).
	register("javascript", len(t.JavaScript), nil, func(idx int) ([]domain.Finding, []error) {
		fs, es, resp := execJavaScript(ctx, t, t.JavaScript[idx-1], target, vars, tvars, e.config.LibraryDir, d)
		vars["javascript_response"] = resp
		return fs, es
	})

	// iterate(x) — nuclei helper: wrap a scalar / undefined into a list so
	// `for (let v of iterate(template.foo))` works whether the extractor
	// produced one value or many.
	vm.Set("iterate", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) == 0 || call.Arguments[0] == nil || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
			return vm.NewArray()
		}
		exported := call.Arguments[0].Export()
		switch v := exported.(type) {
		case []any:
			return vm.ToValue(v)
		case []string:
			out := make([]any, len(v))
			for i, s := range v {
				out[i] = s
			}
			return vm.ToValue(out)
		case string:
			if v == "" {
				return vm.NewArray()
			}
			return vm.ToValue([]any{v})
		default:
			return vm.ToValue([]any{exported})
		}
	})

	// stop() — nuclei early-exit. Interrupt the VM; not reported as a script error.
	vm.Set("stop", func(call goja.FunctionCall) goja.Value {
		stopped = true
		vm.Interrupt(flowStopInterrupt)
		return goja.Undefined()
	})

	// template["x"] = y / template.x and set("x", y) let a flow script pass a
	// value from one step to the next. Both write into the same vars map the
	// bridge functions above already thread into every http/tcp/dns/ssl call,
	// so a value set here is visible to every later call in the script.
	vm.Set("template", vm.NewDynamicObject(&flowVars{vm: vm, vars: vars}))
	vm.Set("set", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 2 {
			return goja.Undefined()
		}
		vars[call.Arguments[0].String()] = call.Arguments[1].Export()
		return goja.Undefined()
	})

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			vm.Interrupt("scan cancelled")
		case <-time.After(flowScriptTimeout):
			vm.Interrupt("flow script timeout")
		case <-done:
		}
	}()
	_, runErr := vm.RunString(t.Flow)
	close(done)
	if runErr != nil && !stopped {
		if ie, ok := runErr.(*goja.InterruptedError); ok {
			if v, _ := ie.Value().(string); v == flowStopInterrupt {
				return findings, errs
			}
		}
		if !isBenignFlowChainBreak(runErr) {
			errs = append(errs, fmt.Errorf("%s: flow script: %w", t.ID, runErr))
		}
	}
	return findings, errs
}

// isBenignFlowChainBreak matches a flow script crashing on exactly goja's own
// "Cannot read property 'x' of undefined[ or null]" TypeError — reproduces
// "CVE-2021-28480: Cannot read property 'toLowerCase' of undefined" and
// "CVE-2024-6670: Cannot read property 'replace' of undefined or null".
// Both templates' flow scripts chain an earlier step's internal extractor
// straight into a method call (`template.servername.toLowerCase()`,
// `template.encryptedPassword.replace(...)`) with no null guard: when the
// target isn't the vulnerable app, step 1's own matcher/extractor finds
// nothing, the chained variable is legitimately undefined, and the very next
// line throws. Real nuclei runs flow scripts on the same goja engine and
// hits the identical TypeError in the identical situation — on a
// non-vulnerable target this is nuclei's own "not vulnerable, stop" signal
// for a flow template, not a defect in our engine, so it must not surface as
// a check error. A flow script error from any other cause (a bridge function
// genuinely missing, "is not a function", a real crash) keeps surfacing
// exactly as before — this only matches goja's fixed wording for the
// null/undefined-property-access TypeError, not failures in general.
func isBenignFlowChainBreak(err error) bool {
	return isBenignUndefinedPropertyAccess(err.Error())
}

// flowVars backs the "template" JS object (template["x"] = y / template.x)
// with the same vars map used for request interpolation and matching, via
// goja's DynamicObject hook — so reads/writes go straight through, no copy.
type flowVars struct {
	vm   *goja.Runtime
	vars map[string]any
}

func (f *flowVars) Get(key string) goja.Value {
	v, ok := f.vars[key]
	if !ok {
		return nil
	}
	return f.vm.ToValue(v)
}

func (f *flowVars) Set(key string, val goja.Value) bool {
	f.vars[key] = val.Export()
	return true
}

func (f *flowVars) Has(key string) bool {
	_, ok := f.vars[key]
	return ok
}

func (f *flowVars) Delete(key string) bool {
	delete(f.vars, key)
	return true
}

func (f *flowVars) Keys() []string {
	keys := make([]string, 0, len(f.vars))
	for k := range f.vars {
		keys = append(keys, k)
	}
	return keys
}
