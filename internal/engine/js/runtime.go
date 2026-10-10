// Package js implements a nuclei-compatible javascript: runtime on goja:
// require("nuclei/…"), Export / ExportAs, isPortOpen, and the bytes helper.
package js

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
)

const defaultDialTimeout = 5 * time.Second

// Result is what a javascript: script leaves for matchers/extractors.
type Result struct {
	Response any
	Success  bool
	Exports  map[string]any
	Error    string
}

// Run executes code with args on a fresh goja VM. preCondition, when non-empty,
// is evaluated first; a falsey / errored precondition skips the main script
// (Success=false, no error — same as nuclei). libraryDir is the permitted
// root for require("nuclei/fs") (empty disables it — see fsModule).
// templateVars backs the `template` global — nuclei's cross-step variable
// bridge, readable/writable from any protocol's script. A flow's http()
// populates it with the response's fields (template.http_all_headers, …)
// before a later javascript() step runs, exactly like flow: scripts' own
// `template.x` binding (internal/engine/flow.go's flowVars) — this is the
// same bridge, just reachable from inside a javascript: block's own VM too.
// nil omits the binding (goja then reports the real
// "ReferenceError: template is not defined" a script using it unexpectedly
// would get from real nuclei too).
func Run(ctx context.Context, code, preCondition string, args map[string]any, templateVars map[string]any, libraryDir string, timeout time.Duration) Result {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", false))

	var exportBuf strings.Builder
	exports := map[string]any{}
	install(vm, runCtx, timeout, libraryDir, &exportBuf, exports)
	if templateVars != nil {
		_ = vm.Set("template", vm.NewDynamicObject(&templateVarsObj{vm: vm, vars: templateVars}))
	}

	for k, v := range args {
		_ = vm.Set(k, coerceArg(v))
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			vm.Interrupt("javascript timeout")
		case <-done:
		}
	}()
	defer close(done)

	if strings.TrimSpace(preCondition) != "" {
		v, err := vm.RunString(wrapScript(preCondition))
		if err != nil {
			return Result{Success: false, Error: err.Error(), Exports: exports}
		}
		if v == nil || goja.IsUndefined(v) || goja.IsNull(v) || !v.ToBoolean() {
			return Result{Success: false, Exports: exports}
		}
	}

	val, err, exited := runMainScript(vm, code)
	if exited {
		// process.exit(...) was called — a template idiom for "stop here,
		// this isn't a match" (see samba-detect.yaml's else branch), not an
		// error: same quiet-skip outcome as a falsey pre-condition.
		return Result{Success: false, Exports: exports, Response: exportBuf.String()}
	}
	if err != nil {
		return Result{Success: false, Error: err.Error(), Exports: exports, Response: exportBuf.String()}
	}

	resp := any(nil)
	if exportBuf.Len() > 0 {
		resp = exportBuf.String()
		if val != nil && !goja.IsUndefined(val) && !goja.IsNull(val) {
			if s := stringify(val, vm); s != "" {
				resp = exportBuf.String() + s
			}
		}
	} else if val != nil && !goja.IsUndefined(val) && !goja.IsNull(val) {
		resp = exportValue(val)
	}

	success := false
	if val != nil && !goja.IsUndefined(val) && !goja.IsNull(val) {
		success = val.ToBoolean()
	} else if exportBuf.Len() > 0 {
		success = true
	}
	return Result{Response: resp, Success: success, Exports: exports}
}

// templateVarsObj backs the `template` global — a goja.DynamicObject over
// the caller's vars map, mirroring internal/engine/flow.go's flowVars
// (same bridge, same shape, just usable from a javascript: block's own VM).
type templateVarsObj struct {
	vm   *goja.Runtime
	vars map[string]any
}

func (t *templateVarsObj) Get(key string) goja.Value {
	v, ok := t.vars[key]
	if !ok {
		return nil
	}
	return t.vm.ToValue(v)
}

func (t *templateVarsObj) Set(key string, val goja.Value) bool {
	t.vars[key] = val.Export()
	return true
}

func (t *templateVarsObj) Has(key string) bool {
	_, ok := t.vars[key]
	return ok
}

func (t *templateVarsObj) Delete(key string) bool {
	delete(t.vars, key)
	return true
}

func (t *templateVarsObj) Keys() []string {
	keys := make([]string, 0, len(t.vars))
	for k := range t.vars {
		keys = append(keys, k)
	}
	return keys
}

// exitSignal is what process.exit panics with — caught by runMainScript,
// never by goja's own exception machinery (that only converts panics of
// goja.Value-wrapped exceptions back into a RunString error; anything else
// propagates past it, which is exactly what lets us distinguish "the
// template called process.exit" from a real script error).
type exitSignal struct{ code int }

// runMainScript runs code and reports whether it stopped via process.exit
// rather than running to completion or throwing.
func runMainScript(vm *goja.Runtime, code string) (val goja.Value, err error, exited bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(exitSignal); ok {
				exited = true
				return
			}
			panic(r)
		}
	}()
	val, err = vm.RunString(wrapScript(code))
	return
}

// InitResult is what an init: script (see domain.JavaScriptRequest.Init)
// leaves behind: payload/arg overrides from calling updatePayload()/set(),
// captured once per execJavaScript call before payload expansion.
type InitResult struct {
	Args     map[string]any
	Payloads map[string]any
	Error    string
}

// RunInit executes an init: script. It gets the same require("nuclei/…")
// surface as a normal script, plus updatePayload(name, value) and
// set(name, value) — real nuclei registers these only for init code (see
// pkg/protocols/javascript/js.go), since they mutate the template itself
// rather than just producing a response.
func RunInit(ctx context.Context, code string, args map[string]any, libraryDir string, timeout time.Duration) InitResult {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", false))

	var exportBuf strings.Builder
	exports := map[string]any{}
	install(vm, runCtx, timeout, libraryDir, &exportBuf, exports)

	argOverrides := map[string]any{}
	payloadOverrides := map[string]any{}
	vm.Set("set", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		if name == "" {
			panic(vm.ToValue("set: variable name cannot be empty"))
		}
		argOverrides[name] = call.Argument(1).Export()
		return goja.Undefined()
	})
	vm.Set("updatePayload", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		if name == "" {
			panic(vm.ToValue("updatePayload: payload name cannot be empty"))
		}
		payloadOverrides[name] = call.Argument(1).Export()
		return goja.Undefined()
	})

	for k, v := range args {
		_ = vm.Set(k, coerceArg(v))
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			vm.Interrupt("javascript timeout")
		case <-done:
		}
	}()
	defer close(done)

	if _, err := vm.RunString(wrapScript(code)); err != nil {
		return InitResult{Error: err.Error()}
	}
	return InitResult{Args: argOverrides, Payloads: payloadOverrides}
}

func install(vm *goja.Runtime, ctx context.Context, timeout time.Duration, libraryDir string, exportBuf *strings.Builder, exports map[string]any) {
	vm.Set("require", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		mod, err := module(vm, ctx, timeout, libraryDir, name)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return mod
	})
	vm.Set("Export", func(call goja.FunctionCall) goja.Value {
		for _, arg := range call.Arguments {
			if s := stringify(arg, vm); s != "" {
				exportBuf.WriteString(s)
			}
		}
		return goja.Null()
	})
	vm.Set("ExportAs", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) != 2 {
			panic(vm.ToValue("ExportAs expects 2 arguments"))
		}
		exports[call.Argument(0).String()] = stringify(call.Argument(1), vm)
		return goja.Null()
	})
	vm.Set("log", func(call goja.FunctionCall) goja.Value {
		return call.Argument(0)
	})
	// to_json is a real nuclei global (distinct from JSON.stringify): it
	// pretty-prints with Go's json.MarshalIndent conventions ("key": value,
	// space after the colon), which is what word/dsl matchers in real
	// templates are written against (e.g. smb-v1-supported.yaml matches the
	// literal substring `"SupportV1": true`— JSON.stringify's compact
	// `"SupportV1":true`, no space, would not match).
	vm.Set("to_json", func(call goja.FunctionCall) goja.Value {
		b, err := json.MarshalIndent(call.Argument(0).Export(), "", "  ")
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(string(b))
	})
	// atob/btoa mirror real nuclei's pkg/js/global/helpers.go exactly,
	// including atob returning null (not throwing) on invalid base64 —
	// CVE-2025-53770.yaml and its siblings do `atob(dg)` on a
	// template-provided variable with no try/catch.
	vm.Set("atob", func(call goja.FunctionCall) goja.Value {
		decoded, err := base64.StdEncoding.DecodeString(call.Argument(0).String())
		if err != nil {
			return goja.Null()
		}
		return vm.ToValue(string(decoded))
	})
	vm.Set("btoa", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(base64.StdEncoding.EncodeToString([]byte(call.Argument(0).String())))
	})
	// Minimal Node-style `process` global: real templates use
	// `process.exit(n)` as a "stop here, no match" idiom (e.g.
	// samba-detect.yaml's else branch) — see exitSignal/runMainScript.
	processObj := vm.NewObject()
	_ = processObj.Set("exit", func(call goja.FunctionCall) goja.Value {
		code := 0
		if len(call.Arguments) > 0 {
			code = int(call.Argument(0).ToInteger())
		}
		panic(exitSignal{code: code})
	})
	_ = vm.Set("process", processObj)
	vm.Set("isPortOpen", func(call goja.FunctionCall) goja.Value {
		host := call.Argument(0).String()
		port := fmt.Sprint(call.Argument(1).Export())
		d := timeout
		if len(call.Arguments) > 2 {
			if n := int(call.Argument(2).ToInteger()); n > 0 {
				d = time.Duration(n) * time.Second
			}
		}
		ok := dialOpen(ctx, "tcp", host, port, d)
		return vm.ToValue(ok)
	})
	vm.Set("isUDPPortOpen", func(call goja.FunctionCall) goja.Value {
		host := call.Argument(0).String()
		port := fmt.Sprint(call.Argument(1).Export())
		d := timeout
		if len(call.Arguments) > 2 {
			if n := int(call.Argument(2).ToInteger()); n > 0 {
				d = time.Duration(n) * time.Second
			}
		}
		ok := dialOpen(ctx, "udp", host, port, d)
		return vm.ToValue(ok)
	})
	// discoveredPorts(host, namePattern) returns the ports our OWN scanner's
	// discovery pass already identified for host whose service Name contains
	// namePattern (e.g. "microsoft-ds") — sourced from the project's real
	// Services list (WithDiscoveredServices, set once per scan in
	// engine.ScanProgress), not a guessed/hardcoded port literal. This is
	// what lets an SMB-specific check (MS17-010, MS08-067) reach whatever
	// port our active SMB identification (internal/discovery/smb_identify.go)
	// actually found — 445, 4445, or anything else a NAT/port-forwarded lab
	// box happens to expose — instead of a static list of guesses.
	vm.Set("discoveredPorts", func(call goja.FunctionCall) goja.Value {
		host := call.Argument(0).String()
		namePattern := call.Argument(1).String()
		ports := portsFor(discoveredServicesFrom(ctx), host, namePattern)
		return vm.ToValue(ports)
	})
	// resolveNetBIOSName / checkZerologon: no upstream nuclei equivalent
	// exists (nuclei's own pkg/js/libs has no RPC/netlogon module at all),
	// so these are plain globals — like isPortOpen/isUDPPortOpen above —
	// rather than a require()'d module built around a class nobody else
	// defines. See netbios.go / dcerpc_zerologon.go.
	vm.Set("resolveNetBIOSName", func(call goja.FunctionCall) goja.Value {
		host := call.Argument(0).String()
		// Capped independently of the ambient (often multi-second) script
		// timeout: a real NBT responder answers in milliseconds, and a
		// dropped/firewalled UDP/137 query gets no ICMP "port unreachable"
		// on many networks, so the read blocks for the full deadline either
		// way — letting it consume the whole script budget would starve
		// whatever runs after it (e.g. checkZerologon's own RPC calls).
		nbtTimeout := timeout
		if nbtTimeout > 2*time.Second || nbtTimeout <= 0 {
			nbtTimeout = 2 * time.Second
		}
		name, err := ResolveNetBIOSName(ctx, host, 137, nbtTimeout)
		if err != nil {
			return goja.Null()
		}
		return vm.ToValue(name)
	})
	vm.Set("checkZerologon", func(call goja.FunctionCall) goja.Value {
		host := call.Argument(0).String()
		computerName := call.Argument(1).String()
		d := timeout
		if len(call.Arguments) > 2 {
			if n := int(call.Argument(2).ToInteger()); n > 0 {
				d = time.Duration(n) * time.Second
			}
		}
		vulnerable, err := CheckZerologon(ctx, host, computerName, d)
		if err != nil {
			return vm.ToValue(false)
		}
		return vm.ToValue(vulnerable)
	})
	// checkMS08067 — see dcerpc_ms08067.go's doc comment: unlike every other
	// global here, the underlying probe itself carries a real (if small)
	// chance of crashing the target's Server service. CVE-2008-4250.yaml
	// carries the `exploit` tag specifically so this never runs without the
	// operator's explicit AllowExploit opt-in.
	vm.Set("checkMS08067", func(call goja.FunctionCall) goja.Value {
		host := call.Argument(0).String()
		port := 445
		if len(call.Arguments) > 1 {
			if p := int(call.Argument(1).ToInteger()); p > 0 {
				port = p
			}
		}
		d := timeout
		if len(call.Arguments) > 2 {
			if n := int(call.Argument(2).ToInteger()); n > 0 {
				d = time.Duration(n) * time.Second
			}
		}
		vulnerable, err := CheckMS08067(ctx, host, port, d)
		if err != nil {
			return vm.ToValue(false)
		}
		return vm.ToValue(vulnerable)
	})
	// checkMS17010 — see smb1_ms17010.go's doc comment: a single, read-only
	// SMB_COM_TRANSACTION probe (nmap's own "safe"-tagged technique), never
	// completing the actual overflow. Takes an explicit port because the
	// vulnerable SMB1 stack is routinely exposed on a non-standard port
	// (e.g. a NAT/port-forwarded lab box on 4445 instead of 445).
	vm.Set("checkMS17010", func(call goja.FunctionCall) goja.Value {
		host := call.Argument(0).String()
		port := 445
		if len(call.Arguments) > 1 {
			if p := int(call.Argument(1).ToInteger()); p > 0 {
				port = p
			}
		}
		d := timeout
		if len(call.Arguments) > 2 {
			if n := int(call.Argument(2).ToInteger()); n > 0 {
				d = time.Duration(n) * time.Second
			}
		}
		vulnerable, err := CheckMS17010(ctx, host, port, d)
		if err != nil {
			return vm.ToValue(false)
		}
		return vm.ToValue(vulnerable)
	})
	// Nuclei preloads `var bytes = require("nuclei/bytes")`.
	bytesMod, _ := module(vm, ctx, timeout, libraryDir, "nuclei/bytes")
	_ = vm.Set("bytes", bytesMod)
}

func module(vm *goja.Runtime, ctx context.Context, timeout time.Duration, libraryDir, name string) (goja.Value, error) {
	switch strings.TrimPrefix(name, "./") {
	case "nuclei/net":
		return netModule(vm, ctx, timeout), nil
	case "nuclei/bytes":
		return bytesModule(vm), nil
	case "nuclei/ssh":
		return sshModule(vm, ctx, timeout), nil
	case "nuclei/redis":
		return redisModule(vm, ctx, timeout), nil
	case "nuclei/mysql":
		return mysqlModule(vm, ctx, timeout), nil
	case "nuclei/postgres":
		return postgresModule(vm, ctx, timeout), nil
	case "nuclei/smb":
		return smbModule(vm, ctx, timeout), nil
	case "nuclei/mssql":
		return mssqlModule(vm, ctx, timeout), nil
	case "nuclei/fs":
		return fsModule(vm, libraryDir), nil
	case "nuclei/vnc":
		return vncModule(vm, ctx, timeout), nil
	case "nuclei/rdp":
		return rdpModule(vm, ctx, timeout), nil
	case "nuclei/ldap":
		return ldapModule(vm, ctx, timeout), nil
	case "nuclei/oracle", "nuclei/rsync", "nuclei/smtp":
		return stubModule(vm, name), nil
	default:
		return nil, fmt.Errorf("unknown module %q", name)
	}
}

func stubModule(vm *goja.Runtime, name string) goja.Value {
	obj := vm.NewObject()
	_ = obj.Set("__name", name)
	_ = obj.Set("__stub", true)
	return obj
}

func dialOpen(ctx context.Context, network, host, port string, timeout time.Duration) bool {
	if host == "" || port == "" {
		return false
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, network, net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func wrapScript(code string) string {
	// Run as a script (not an IIFE): goja returns the value of the last
	// expression statement, matching nuclei precondition / bare-result style
	// (`isPortOpen(Host,Port)` → bool, final `resp;` → response).
	return code
}

func stringify(v goja.Value, vm *goja.Runtime) string {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return ""
	}
	exported := v.Export()
	switch x := exported.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case bool, int, int64, float64:
		return fmt.Sprint(x)
	default:
		// Indented, not compact: real nuclei templates that Export()/
		// ExportAs() an object and then word/dsl-match a literal substring
		// are written against the "key": value (space after colon) shape
		// json.MarshalIndent produces — same reasoning as to_json below.
		b, err := json.MarshalIndent(exported, "", "  ")
		if err != nil {
			return fmt.Sprint(exported)
		}
		return string(b)
	}
}

func exportValue(v goja.Value) any {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}
	return v.Export()
}

func coerceArg(v any) any {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		if x == float64(int(x)) {
			return int(x)
		}
		return x
	case bool:
		return x
	default:
		return fmt.Sprint(v)
	}
}

func asHostPort(host any, port any) (string, int, error) {
	h := strings.TrimSpace(fmt.Sprint(host))
	if h == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	switch p := port.(type) {
	case int:
		return h, p, nil
	case int64:
		return h, int(p), nil
	case float64:
		return h, int(p), nil
	default:
		s := strings.TrimSpace(fmt.Sprint(port))
		n, err := strconv.Atoi(s)
		if err != nil {
			return "", 0, fmt.Errorf("bad port %q", s)
		}
		return h, n, nil
	}
}

func joinAddr(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
