// Package nse runs Nmap NSE (.nse Lua) scripts in-process using an embedded
// Lua interpreter instead of the external nmap binary. All network I/O a script
// performs is routed through a controlled layer (see net.go) so the engine —
// not the script — owns rate limiting, timeouts and cancellation.
//
// Pure-Lua nselib modules under library/nmap/nselib are loaded with a Lua 5.3
// compatibility transform. C modules openssl/lpeg/libssh2 are Go stubs.
package nse

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

type HostInfo struct {
	IP   string
	Name string // domain/targetname if the target was a name, else IP
}

type PortInfo struct {
	Number   int
	Protocol string
	State    string
	Service  string
	Product  string
	Version  string
	Tunnel   string
}

type ScriptResult struct {
	ScriptID string
	Port     int // 0 for host-level scripts
	Output   string
}

type Config struct {
	SelectedServicesOnly bool
	Complete             bool
	Timeout              time.Duration // Per network operation.
	ScriptTimeout        time.Duration // Total budget for one script across all selected ports.
	RPS                  int
	Args                 map[string]string
}

// DefaultBruteArgs derives nmap's brute-force safety script-args
// (brute.threads, brute.delay — see library/nmap/nselib/brute.lua) from the
// scan's own speed settings. Without this, a brute-tagged NSE script falls
// back to nmap's own aggressive defaults (20 threads, 0 delay between
// guesses) regardless of how gently the pentester configured the rest of
// the scan: our RPS limiter throttles each new connection a script opens,
// but a script sending several guesses over one already-open connection
// (brute.lua's "threads" reuse connections) isn't covered by that — only
// the script's own brute.delay sees each individual guess. Call this once
// per project/run and merge the result into Config.Args; it never
// overrides an explicit brute.* value the caller already set.
func DefaultBruteArgs(rps, concurrency int) map[string]string {
	args := map[string]string{}
	if concurrency > 0 {
		args["brute.threads"] = strconv.Itoa(concurrency)
	}
	if rps > 0 {
		args["brute.delay"] = strconv.FormatFloat(1/float64(rps), 'f', -1, 64)
	}
	return args
}

type Runner struct {
	libraryDir string
	cfg        Config
}

func New(libraryDir string, cfg Config) *Runner {
	return &Runner{libraryDir: libraryDir, cfg: cfg}
}

var moduleNotFoundRE = regexp.MustCompile(`module '?([A-Za-z0-9_.]+)'? not found`)

// Run loads one NSE script and runs it against the given host/ports. It returns
// the script's findings, whether it actually executed (false when skipped), and
// an error describing why it could not run (such as an unsupported library).
// ScriptTimeLimit bounds scripts with repeated network calls as well as Lua loops.
// The default allows three network timeouts, with a minimum of 30 seconds.
func (r *Runner) ScriptTimeLimit() time.Duration {
	if r.cfg.ScriptTimeout > 0 {
		return r.cfg.ScriptTimeout
	}
	return max(30*time.Second, 3*r.cfg.Timeout)
}

func (r *Runner) Run(ctx context.Context, scriptPath string, host HostInfo, ports []PortInfo) ([]ScriptResult, bool, error) {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, r.ScriptTimeLimit())
	defer cancel()
	results, ran, err := r.run(ctx, scriptPath, host, ports)
	if parent.Err() != nil {
		return results, ran, parent.Err()
	}
	if ctx.Err() != nil {
		return results, ran, fmt.Errorf("%s: общий таймаут скрипта %s: %w", filepath.Base(scriptPath), r.ScriptTimeLimit(), ctx.Err())
	}
	return results, ran, err
}

func (r *Runner) run(ctx context.Context, scriptPath string, host HostInfo, ports []PortInfo) ([]ScriptResult, bool, error) {
	// NSE scripts run on our own native Lua engine only — never shell out to the
	// external nmap binary.
	source, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, false, err
	}
	scriptID := strings.TrimSuffix(filepath.Base(scriptPath), ".nse")
	if nativeDatabaseScript(scriptID) {
		return r.runDatabaseCredentials(ctx, scriptID, host, ports)
	}
	if scriptID == "telnet-brute" {
		return r.runTelnetBrute(ctx, host, ports)
	}

	cfg := r.cfg
	if cfg.SelectedServicesOnly {
		cfg.Args = map[string]string{}
		for k, v := range r.cfg.Args {
			cfg.Args[k] = v
		}
		cfg.Args["mssql.scanned-ports-only"] = "true"
		if len(ports) == 1 && ports[0].Protocol != "udp" {
			cfg.Args["mssql.instance-port"] = strconv.Itoa(ports[0].Number)
		}
		r = New(r.libraryDir, cfg)
	}
	ctrl := newControl(ctx, r.cfg)
	if cfg.SelectedServicesOnly {
		ctrl.bindScope(host, ports)
	}
	defer ctrl.close()

	L := lua.NewState()
	defer L.Close()
	L.SetContext(ctx)
	sandbox(L)
	registerSocketType(L)
	r.registerModules(L, ctrl, scriptID)
	L.SetGlobal("SCRIPT_NAME", lua.LString(scriptID))
	L.SetGlobal("SCRIPT_TYPE", lua.LString("portrule"))

	// .nse files are Lua 5.3 upstream; transform before load (same as nselib).
	if err := L.DoString(transformLua53(string(source))); err != nil {
		if m := moduleNotFoundRE.FindStringSubmatch(err.Error()); m != nil {
			return nil, false, fmt.Errorf("%s: не поддерживается (нужна библиотека NSE %q)", scriptID, m[1])
		}
		return nil, false, fmt.Errorf("%s: ошибка загрузки: %v", scriptID, err)
	}

	if databaseSequentialBrute(scriptID) {
		if err := installDatabaseBrute(L); err != nil {
			return nil, false, err
		}
	}

	hostTbl := r.hostTable(L, host, ports)

	portrule := L.GetGlobal("portrule")
	hostrule := L.GetGlobal("hostrule")
	action := L.GetGlobal("action")
	actionFn, ok := action.(*lua.LFunction)
	if !ok {
		return nil, false, fmt.Errorf("%s: нет функции action", scriptID)
	}

	var results []ScriptResult
	var runErrors []error
	ran := false
	if fn, ok := portrule.(*lua.LFunction); ok {
		for _, p := range ports {
			if ctx.Err() != nil {
				return results, len(results) > 0, ctx.Err()
			}
			portTbl := r.portTable(L, p)
			pass, err := callBool(L, fn, hostTbl, portTbl)
			if err != nil {
				runErrors = append(runErrors, fmt.Errorf("%s %d/%s portrule: %w", scriptID, p.Number, p.Protocol, err))
				continue
			}
			if !pass {
				continue
			}
			ran = true
			ctrl.commErrors = nil
			out, err := callAction(L, actionFn, hostTbl, portTbl)
			if err != nil {
				runErrors = append(runErrors, fmt.Errorf("%s %d/%s action: %w", scriptID, p.Number, p.Protocol, err))
				continue
			}
			if out != "" {
				if OutputIsError(out) && len(ctrl.commErrors) > 0 {
					out += "\n" + errors.Join(ctrl.commErrors...).Error()
				}
				results = append(results, ScriptResult{ScriptID: scriptID, Port: p.Number, Output: out})
			}
		}
		return results, ran, errors.Join(runErrors...)
	}
	if fn, ok := hostrule.(*lua.LFunction); ok {
		pass, err := callBool(L, fn, hostTbl)
		if err != nil {
			return nil, false, fmt.Errorf("%s hostrule: %w", scriptID, err)
		}
		if !pass {
			return nil, false, nil
		}
		out, err := callAction(L, actionFn, hostTbl)
		if err != nil {
			return nil, true, fmt.Errorf("%s action: %w", scriptID, err)
		}
		if out != "" {
			results = append(results, ScriptResult{ScriptID: scriptID, Port: 0, Output: out})
		}
		return results, true, nil
	}
	return nil, false, fmt.Errorf("%s: нет portrule/hostrule", scriptID)
}

func (r *Runner) hostTable(L *lua.LState, host HostInfo, ports []PortInfo) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "ip", lua.LString(host.IP))
	L.SetField(t, "name", lua.LString(host.Name))
	L.SetField(t, "targetname", lua.LString(host.Name))
	// host:targetname() style is sometimes used; expose as table fields only.
	L.SetField(t, "os", L.NewTable())
	L.SetField(t, "registry", L.NewTable())
	portsTbl := L.NewTable()
	for i, p := range ports {
		portsTbl.RawSetInt(i+1, r.portTable(L, p))
	}
	L.SetField(t, "ports", portsTbl)
	return t
}

func (r *Runner) portTable(L *lua.LState, p PortInfo) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "number", lua.LNumber(p.Number))
	proto := p.Protocol
	if proto == "" {
		proto = "tcp"
	}
	L.SetField(t, "protocol", lua.LString(proto))
	state := p.State
	if state == "" {
		state = "open"
	}
	L.SetField(t, "state", lua.LString(state))
	service := p.Service
	if service == "" {
		service = "unknown"
	}
	switch strings.ToLower(service) {
	case "mssql", "ms-sql", "sqlserver":
		service = "ms-sql-s"
	case "mssql-browser", "sql-browser":
		service = "ms-sql-m"
	}
	L.SetField(t, "service", lua.LString(service))
	version := L.NewTable()
	L.SetField(version, "name", lua.LString(service))
	L.SetField(version, "name_confidence", lua.LNumber(0))
	L.SetField(version, "product", lua.LString(p.Product))
	L.SetField(version, "version", lua.LString(p.Version))
	if p.Tunnel != "" {
		L.SetField(version, "service_tunnel", lua.LString(p.Tunnel))
	}
	L.SetField(t, "version", version)
	return t
}

// callBool invokes a rule function and coerces the first return to a boolean.
func callBool(L *lua.LState, fn *lua.LFunction, args ...lua.LValue) (bool, error) {
	top := L.GetTop()
	defer L.SetTop(top)
	if err := L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, args...); err != nil {
		return false, err
	}
	ret := L.Get(-1)
	L.Pop(1)
	return lua.LVAsBool(ret), nil
}

// callAction invokes an action function and reduces its returns to the plain
// text output a finding carries.
func callAction(L *lua.LState, fn *lua.LFunction, args ...lua.LValue) (string, error) {
	top := L.GetTop()
	defer L.SetTop(top)
	if err := L.CallByParam(lua.P{Fn: fn, NRet: lua.MultRet, Protect: true}, args...); err != nil {
		return "", err
	}
	n := L.GetTop() - top
	if n <= 0 {
		return "", nil
	}
	rets := make([]lua.LValue, n)
	for i := 0; i < n; i++ {
		rets[i] = L.Get(top + 1 + i)
	}
	L.Pop(n)
	// Prefer a trailing string return (NSE's human-readable output); otherwise
	// render the first table/string.
	for i := len(rets) - 1; i >= 0; i-- {
		if s, ok := rets[i].(lua.LString); ok {
			return strings.TrimSpace(string(s)), nil
		}
	}
	if len(rets) > 0 {
		if tbl, ok := rets[0].(*lua.LTable); ok {
			return flattenTable(tbl), nil
		}
	}
	return "", nil
}

// flattenTable renders a Lua table of results as "key: value" lines, a simple
// stand-in for nmap's structured output formatter. Honors stdnse.output_table
// proxies that store data behind an __index metatable.
func flattenTable(t *lua.LTable) string {
	var lines []string
	var add func(k, v lua.LValue)
	add = func(k, v lua.LValue) {
		switch val := v.(type) {
		case *lua.LTable:
			if inner := flattenTable(val); inner != "" {
				if ks, ok := k.(lua.LString); ok && string(ks) != "" {
					lines = append(lines, string(ks)+":")
					for _, ln := range strings.Split(inner, "\n") {
						lines = append(lines, "  "+ln)
					}
				} else {
					lines = append(lines, inner)
				}
			}
		default:
			if v == lua.LNil {
				return
			}
			s := strings.TrimSpace(v.String())
			if s == "" {
				return
			}
			if ks, ok := k.(lua.LString); ok {
				lines = append(lines, string(ks)+": "+s)
			} else {
				lines = append(lines, s)
			}
		}
	}
	t.ForEach(add)
	if len(lines) == 0 && t.Metatable != nil {
		if mt, ok := t.Metatable.(*lua.LTable); ok {
			if idx, ok := mt.RawGetString("__index").(*lua.LTable); ok {
				idx.ForEach(add)
			}
		}
	}
	return strings.Join(lines, "\n")
}

// sandbox removes the clearly dangerous surface from a fresh Lua state while
// leaving the standard string/table/math/os-time helpers scripts rely on.
func sandbox(L *lua.LState) {
	if osv, ok := L.GetGlobal("os").(*lua.LTable); ok {
		for _, name := range []string{"execute", "exit", "remove", "rename", "setenv", "tmpname"} {
			L.SetField(osv, name, lua.LNil)
		}
	}
	if iov, ok := L.GetGlobal("io").(*lua.LTable); ok {
		// popen would shell out, defeating the point of an in-process engine.
		L.SetField(iov, "popen", lua.LNil)
	}
	if pkg, ok := L.GetGlobal("package").(*lua.LTable); ok {
		L.SetField(pkg, "loadlib", lua.LNil)
	}
	L.SetGlobal("dofile", lua.LNil)
	L.SetGlobal("loadfile", lua.LNil)
}
