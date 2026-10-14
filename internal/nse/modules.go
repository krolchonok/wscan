package nse

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// registerModules preloads the subset of the NSE library surface this engine
// implements, each backed by the controlled network layer, then wires nselib.
func (r *Runner) registerModules(L *lua.LState, ctrl *control, scriptID string) {
	registry := L.NewTable()
	args := L.NewTable()
	for k, v := range r.cfg.Args {
		L.SetField(args, k, lua.LString(v))
	}
	L.SetField(registry, "args", args)

	registerBitLib(L)
	registerStringPack(L)
	registerMathToInteger(L)
	registerTableUnpack(L)
	registerUTF8(L)
	registerOpenSSL(L)
	registerUnitTestStub(L)
	registerLFSStub(L)
	registerLPegStub(L)
	registerNmapDBStub(L)
	registerLibSSH2Stub(L)

	preload := func(name string, fns map[string]lua.LGFunction, after func(mod *lua.LTable)) {
		L.PreloadModule(name, func(L *lua.LState) int {
			mod := L.SetFuncs(L.NewTable(), fns)
			if after != nil {
				after(mod)
			}
			L.Push(mod)
			return 1
		})
	}

	preload("nmap", map[string]lua.LGFunction{
		"new_socket":       ctrl.newSocketFn,
		"get_port_state":   nmapGetPortState,
		"get_ports":        nmapGetPorts,
		"set_port_version": noop,
		"port_is_excluded": constFalse,
		"verbosity":        constZero,
		"debugging":        constZero,
		"timing_level":     func(L *lua.LState) int { L.Push(lua.LNumber(3)); return 1 },
		"condvar": func(L *lua.LState) int {
			L.RaiseError("NSE coroutine scheduler is not supported by the native engine")
			return 0
		},
		// Real nmap's default --version-intensity is 7; shortport.
		// version_port_or_service() gates on `nmap.version_intensity() >=
		// rarity` (rarity defaults to 7 too) — without this function at
		// all, any script using that portrule (tftp-version.nse, …) failed
		// to even load with "attempt to call a non-function object".
		"version_intensity": func(L *lua.LState) int { L.Push(lua.LNumber(7)); return 1 },
		"log_write":         noop,
		"new_try":           nmapNewTry,
		"mutex":             nmapMutex,
		"registry_add_host": noop,
		// fetchfile resolves a path relative to nmap's datadir (real nmap
		// searches --datadir/$NMAPDATADIR/the install share; ours is just
		// library/nmap/) and returns it, or nil if missing — same contract
		// as real nmap, which returns a path for the caller to open, not the
		// file's contents. Was entirely missing: any script calling it
		// (e.g. ssh-publickey-acceptance.nse's
		// nmap.fetchfile("nselib/data/publickeydb")) failed to even load
		// with "attempt to call a non-function object".
		"fetchfile": func(L *lua.LState) int {
			rel := L.CheckString(1)
			path := filepath.Join(r.libraryDir, "nmap", filepath.FromSlash(rel))
			if _, err := os.Stat(path); err != nil {
				L.Push(lua.LNil)
				return 1
			}
			L.Push(lua.LString(path))
			return 1
		},
	}, func(mod *lua.LTable) {
		L.SetField(mod, "registry", registry)
		registerNmapSocket(L, mod)
	})

	preload("stdnse", map[string]lua.LGFunction{
		"get_timeout":     func(L *lua.LState) int { L.Push(lua.LNumber(ctrl.timeout.Milliseconds())); return 1 },
		"get_script_args": r.stdnseGetScriptArgs,
		"format_output":   stdnseFormatOutput,
		"output_table":    stdnseOutputTable,
		"strsplit":        stdnseStrsplit,
		"strjoin":         stdnseStrjoin,
		"tostr":           stdnseTostr,
		"tohex":           stdnseTohex,
		"fromhex":         stdnseFromhex,
		"string_or_blank": stdnseStringOrBlank,
		"module":          stdnseModule,
		"seeall":          stdnseSeeall,
		"silent_require":  stdnseSilentRequire,
		"parse_timespec":  stdnseParseTimespec,
		"make_buffer":     stdnseMakeBuffer,
		"debug":           noop, "debug1": noop, "debug2": noop, "debug3": noop, "debug4": noop, "debug5": noop,
		"verbose": noop, "verbose1": noop, "print_debug": noop, "print_verbose": noop, "log": noop,
		"sleep":        ctrl.sleepFn,
		"get_hostname": stdnseGetHostname,
		"clock_ms":     func(L *lua.LState) int { L.Push(lua.LNumber(time.Now().UnixMilli())); return 1 },
	}, nil)

	preload("shortport", map[string]lua.LGFunction{
		"http":                    shortportHTTP,
		"ssl":                     shortportSSL,
		"ssh":                     shortportSSH,
		"port_or_service":         shortportPortOrService,
		"version_port_or_service": shortportVersionPortOrService,
		"portnumber":              shortportPortNumber,
		"service":                 shortportService,
	}, nil)

	preload("http", map[string]lua.LGFunction{
		"get":     ctrl.httpGet,
		"head":    ctrl.httpHead,
		"post":    ctrl.httpPost,
		"get_url": ctrl.httpGetURL,
	}, nil)

	preload("comm", map[string]lua.LGFunction{
		"exchange":   ctrl.commExchange,
		"get_banner": ctrl.commGetBanner,
		"opencon":    ctrl.commOpencon,
		"tryssl":     ctrl.commTrySSL,
	}, nil)

	preload("url", map[string]lua.LGFunction{
		"escape":   urlEscape,
		"unescape": urlUnescape,
		"absolute": urlAbsolute,
		"parse":    urlParse,
	}, nil)

	r.registerNselibLoader(L)
}

// --- shared tiny helpers -------------------------------------------------

func noop(L *lua.LState) int       { return 0 }
func constFalse(L *lua.LState) int { L.Push(lua.LFalse); return 1 }
func constZero(L *lua.LState) int  { L.Push(lua.LNumber(0)); return 1 }

func (c *control) newSocketFn(L *lua.LState) int {
	ud := L.NewUserData()
	sock := &luaSocket{ctrl: c}
	c.sockets = append(c.sockets, sock)
	ud.Value = sock
	L.SetMetatable(ud, L.GetTypeMetatable(socketType))
	L.Push(ud)
	return 1
}

// nmapGetPortState mirrors nmap.get_port_state(host, port): look up a scanned
// port on host.ports by number+protocol. Returns the port table or nil.
func nmapGetPortState(L *lua.LState) int {
	host := L.CheckTable(1)
	num, proto := portQuery(L, L.Get(2))
	if num == 0 {
		L.Push(lua.LNil)
		return 1
	}
	if proto == "" {
		proto = "tcp"
	}
	ports, ok := L.GetField(host, "ports").(*lua.LTable)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	var found lua.LValue = lua.LNil
	ports.ForEach(func(_, v lua.LValue) {
		if found != lua.LNil {
			return
		}
		pt, ok := v.(*lua.LTable)
		if !ok {
			return
		}
		n := int(lua.LVAsNumber(L.GetField(pt, "number")))
		p := L.GetField(pt, "protocol").String()
		if p == "" {
			p = "tcp"
		}
		if n == num && strings.EqualFold(p, proto) {
			found = pt
		}
	})
	L.Push(found)
	return 1
}

func portQuery(L *lua.LState, v lua.LValue) (int, string) {
	switch x := v.(type) {
	case lua.LNumber:
		return int(x), "tcp"
	case *lua.LTable:
		num := int(lua.LVAsNumber(L.GetField(x, "number")))
		proto := L.GetField(x, "protocol").String()
		return num, proto
	default:
		if n, err := strconv.Atoi(v.String()); err == nil {
			return n, "tcp"
		}
		return 0, ""
	}
}

// nmapMutex returns a no-op mutex callable ("lock"/"trylock"/"done"/"running").
// Single-threaded script execution does not need real locking.
func nmapMutex(L *lua.LState) int {
	fn := L.NewFunction(func(L *lua.LState) int {
		op := L.OptString(1, "")
		switch op {
		case "trylock":
			L.Push(lua.LTrue)
			return 1
		case "running":
			L.Push(lua.LNil)
			return 1
		default:
			// lock / done / unknown — no-op
			return 0
		}
	})
	L.Push(fn)
	return 1
}

// nmapNewTry returns a `try` function: try(ok, ...) raises on a false/nil ok,
// otherwise returns the remaining values.
func nmapNewTry(L *lua.LState) int {
	try := L.NewFunction(func(L *lua.LState) int {
		n := L.GetTop()
		if n == 0 {
			return 0
		}
		ok := L.Get(1)
		if ok == lua.LNil || ok == lua.LFalse {
			msg := "try failed"
			if n >= 2 {
				msg = L.Get(2).String()
			}
			L.RaiseError("%s", msg)
			return 0
		}
		for i := 2; i <= n; i++ {
			L.Push(L.Get(i))
		}
		return n - 1
	})
	L.Push(try)
	return 1
}

func (c *control) sleepFn(L *lua.LState) int {
	sec := float64(L.OptNumber(1, 0))
	d := time.Duration(sec * float64(time.Second))
	if d > c.timeout {
		d = c.timeout
	}
	if d <= 0 {
		return 0
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-c.ctx.Done():
	case <-t.C:
	}
	return 0
}

// --- stdnse --------------------------------------------------------------

func (r *Runner) stdnseGetScriptArgs(L *lua.LState) int {
	n := L.GetTop()
	for i := 1; i <= n; i++ {
		value := lua.LValue(lua.LNil)
		lookup := func(name string) {
			if value == lua.LNil {
				if v, ok := r.cfg.Args[name]; ok {
					value = lua.LString(v)
				}
			}
		}
		switch arg := L.Get(i).(type) {
		case lua.LString:
			lookup(string(arg))
		case *lua.LTable:
			for j := 1; j <= arg.Len(); j++ {
				name, ok := arg.RawGetInt(j).(lua.LString)
				if !ok {
					L.ArgError(i, "aliases must contain strings")
					return 0
				}
				lookup(string(name))
			}
		default:
			L.ArgError(i, "string or table of aliases expected")
			return 0
		}
		L.Push(value)
	}
	return n
}

func stdnseOutputTable(L *lua.LState) int {
	data := L.NewTable()
	order := L.NewTable()
	proxy := L.NewTable()
	mt := L.NewTable()
	L.SetField(mt, "__newindex", L.NewFunction(func(L *lua.LState) int {
		k, v := L.Get(2), L.Get(3)
		existing := L.GetTable(data, k)
		if existing == lua.LNil && v != lua.LNil {
			order.Append(k)
		} else if v == lua.LNil && existing != lua.LNil {
			// remove k from order
			n := order.Len()
			for i := 1; i <= n; i++ {
				if L.RawGetInt(order, i) == k {
					for j := i; j < n; j++ {
						order.RawSetInt(j, L.RawGetInt(order, j+1))
					}
					order.RawSetInt(n, lua.LNil)
					break
				}
			}
		}
		L.SetTable(data, k, v)
		return 0
	}))
	L.SetField(mt, "__index", data)
	L.SetField(mt, "__len", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(order.Len()))
		return 1
	}))
	L.SetField(mt, "__call", L.NewFunction(func(L *lua.LState) int {
		if order.Len() > 0 {
			L.Push(lua.LTrue)
		} else {
			L.Push(lua.LFalse)
		}
		return 1
	}))
	L.SetField(mt, "__pairs", L.NewFunction(func(L *lua.LState) int {
		i := 0
		iter := L.NewFunction(func(L *lua.LState) int {
			i++
			if i > order.Len() {
				L.Push(lua.LNil)
				return 1
			}
			k := L.RawGetInt(order, i)
			L.Push(k)
			L.Push(L.GetTable(data, k))
			return 2
		})
		L.Push(iter)
		return 1
	}))
	L.SetMetatable(proxy, mt)
	L.Push(proxy)
	return 1
}

func stdnseFormatOutput(L *lua.LState) int {
	// format_output(status, data): return data rendered as text.
	data := L.Get(2)
	switch v := data.(type) {
	case lua.LString:
		L.Push(v)
	case *lua.LTable:
		L.Push(lua.LString(flattenTable(v)))
	default:
		L.Push(lua.LString(data.String()))
	}
	return 1
}

func stdnseStrsplit(L *lua.LState) int {
	sep := L.CheckString(1)
	s := L.CheckString(2)
	out := L.NewTable()
	parts := strings.Split(s, sep)
	for _, p := range parts {
		out.Append(lua.LString(p))
	}
	L.Push(out)
	return 1
}

func stdnseStrjoin(L *lua.LState) int {
	sep := L.CheckString(1)
	tbl := L.CheckTable(2)
	var parts []string
	tbl.ForEach(func(_, v lua.LValue) { parts = append(parts, v.String()) })
	L.Push(lua.LString(strings.Join(parts, sep)))
	return 1
}

func stdnseTostr(L *lua.LState) int {
	L.Push(lua.LString(L.Get(1).String()))
	return 1
}

func stdnseTohex(L *lua.LState) int {
	v := L.Get(1)
	var hex string
	switch x := v.(type) {
	case lua.LNumber:
		hex = fmt.Sprintf("%x", uint64(x))
	case lua.LString:
		var b strings.Builder
		for i := 0; i < len(x); i++ {
			b.WriteString(fmt.Sprintf("%02x", x[i]))
		}
		hex = b.String()
	default:
		L.RaiseError("Type not supported in tohex(): %s", v.Type())
		return 0
	}
	if opts, ok := L.Get(2).(*lua.LTable); ok {
		sep := L.GetField(opts, "separator").String()
		if sep != "" && sep != "nil" {
			group := int(lua.LVAsNumber(L.GetField(opts, "group")))
			if group <= 0 {
				group = 2
			}
			extra := (group - len(hex)%group) % group
			if extra > 0 {
				hex = strings.Repeat("0", extra) + hex
			}
			var parts []string
			for i := 0; i < len(hex); i += group {
				end := i + group
				if end > len(hex) {
					end = len(hex)
				}
				parts = append(parts, hex[i:end])
			}
			hex = strings.Join(parts, sep)
		}
	}
	L.Push(lua.LString(hex))
	return 1
}

func stdnseFromhex(L *lua.LState) int {
	s := L.CheckString(1)
	s = strings.ReplaceAll(s, " ", "")
	b := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		var v byte
		fmt.Sscanf(s[i:i+2], "%02x", &v)
		b = append(b, v)
	}
	L.Push(lua.LString(string(b)))
	return 1
}

func stdnseStringOrBlank(L *lua.LState) int {
	s := L.OptString(1, "")
	blank := L.OptString(2, "")
	if s == "" {
		L.Push(lua.LString(blank))
	} else {
		L.Push(lua.LString(s))
	}
	return 1
}

func stdnseModule(L *lua.LState) int {
	name := L.OptString(1, "")
	env := L.NewTable()
	L.SetField(env, "_NAME", lua.LString(name))
	L.SetField(env, "_M", env)
	if i := strings.LastIndex(name, "."); i > 0 {
		L.SetField(env, "_PACKAGE", lua.LString(name[:i]))
	}
	for i := 2; i <= L.GetTop(); i++ {
		if fn, ok := L.Get(i).(*lua.LFunction); ok {
			L.Push(fn)
			L.Push(env)
			if err := L.PCall(1, 0, nil); err != nil {
				L.RaiseError("%v", err)
				return 0
			}
		}
	}
	L.Push(env)
	return 1
}

func stdnseSeeall(L *lua.LState) int {
	env := L.CheckTable(1)
	mt := L.GetMetatable(env)
	var mtt *lua.LTable
	if mt == lua.LNil {
		mtt = L.NewTable()
		L.SetMetatable(env, mtt)
	} else {
		mtt = mt.(*lua.LTable)
	}
	L.SetField(mtt, "__index", L.Get(lua.GlobalsIndex))
	return 0
}

// stdnseSilentRequire mirrors nmap's stdnse.silent_require: require() that
// returns nil instead of raising when a module is missing.
func stdnseSilentRequire(L *lua.LState) int {
	name := L.CheckString(1)
	top := L.GetTop()
	L.Push(L.GetGlobal("require"))
	L.Push(lua.LString(name))
	if err := L.PCall(1, 1, nil); err != nil {
		L.SetTop(top)
		L.Push(lua.LNil)
		return 1
	}
	return 1
}

// stdnseParseTimespec parses NSE timespecs like "30m", "10s", "100ms" into seconds.
func stdnseParseTimespec(L *lua.LState) int {
	if L.Get(1) == lua.LNil {
		L.Push(lua.LNil)
		L.Push(lua.LString("Can't parse nil timespec"))
		return 2
	}
	spec := L.CheckString(1)
	mult := map[string]float64{
		"": 1, "s": 1, "ms": 0.001, "m": 60, "h": 3600, "d": 86400,
	}
	var numStr, unit string
	for i, r := range spec {
		if (r >= '0' && r <= '9') || r == '.' {
			continue
		}
		numStr = spec[:i]
		unit = spec[i:]
		break
	}
	if numStr == "" {
		numStr = spec
	}
	n, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("Can't parse time specification %q", spec)))
		return 2
	}
	m, ok := mult[unit]
	if !ok {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("Can't parse time specification %q (bad unit %q)", spec, unit)))
		return 2
	}
	L.Push(lua.LNumber(n * m))
	return 1
}

func stdnseGetHostname(L *lua.LState) int {
	host := L.CheckTable(1)
	if name := L.GetField(host, "targetname"); name != lua.LNil && name.String() != "" {
		L.Push(name)
		return 1
	}
	L.Push(L.GetField(host, "ip"))
	return 1
}

// --- shortport -----------------------------------------------------------

func portFields(L *lua.LState, idx int) (number int, service string) {
	t, ok := L.Get(idx).(*lua.LTable)
	if !ok {
		return 0, ""
	}
	number = int(lua.LVAsNumber(L.GetField(t, "number")))
	service = strings.ToLower(L.GetField(t, "service").String())
	return
}

func isWebPort(number int, service string) bool {
	if strings.Contains(service, "http") {
		return true
	}
	switch number {
	case 80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 9090:
		return true
	}
	return false
}

func shortportHTTP(L *lua.LState) int {
	number, service := portFields(L, 2)
	L.Push(lua.LBool(isWebPort(number, service)))
	return 1
}

// likelySSHPorts/likelySSHServices mirror LIKELY_SSH_PORTS/LIKELY_SSH_SERVICES
// in the real nselib/shortport.lua (vendored in library/nmap/nselib/
// shortport.lua) — our shortport module is a native Go reimplementation, not
// a load of that .lua file, so it has to carry this list by hand. ssh.nse
// scripts commonly write `portrule = shortport.ssh` directly (same calling
// shape as shortport.http/.ssl: a portrule itself, not a factory like
// port_or_service), which was missing here entirely — every such script
// failed to find any portrule/hostrule at all.
var (
	likelySSHPorts    = map[int]bool{22: true, 2222: true, 55554: true, 22222: true, 2382: true, 830: true}
	likelySSHServices = map[string]bool{"ssh": true, "netconf-ssh": true}
)

func shortportSSH(L *lua.LState) int {
	number, service := portFields(L, 2)
	L.Push(lua.LBool(likelySSHPorts[number] || likelySSHServices[service]))
	return 1
}

func shortportSSL(L *lua.LState) int {
	t, _ := L.Get(2).(*lua.LTable)
	number, service := portFields(L, 2)
	ssl := strings.Contains(service, "https") || strings.Contains(service, "ssl") || number == 443 || number == 8443
	if t != nil {
		if ver, ok := L.GetField(t, "version").(*lua.LTable); ok {
			if L.GetField(ver, "service_tunnel").String() == "ssl" {
				ssl = true
			}
		}
	}
	L.Push(lua.LBool(ssl))
	return 1
}

// collectInts/collectStrings accept a Lua number/string or a table of them.
func collectInts(v lua.LValue) map[int]bool {
	out := map[int]bool{}
	switch x := v.(type) {
	case lua.LNumber:
		out[int(x)] = true
	case *lua.LTable:
		x.ForEach(func(_, e lua.LValue) {
			if n, ok := e.(lua.LNumber); ok {
				out[int(n)] = true
			}
		})
	}
	return out
}

func collectStrings(v lua.LValue) map[string]bool {
	out := map[string]bool{}
	switch x := v.(type) {
	case lua.LString:
		out[strings.ToLower(string(x))] = true
	case *lua.LTable:
		x.ForEach(func(_, e lua.LValue) {
			if s, ok := e.(lua.LString); ok {
				out[strings.ToLower(string(s))] = true
			}
		})
	}
	return out
}

func matcherFunc(L *lua.LState, numbers map[int]bool, services map[string]bool) int {
	fn := L.NewFunction(func(L *lua.LState) int {
		number, service := portFields(L, 2)
		L.Push(lua.LBool(numbers[number] || services[service]))
		return 1
	})
	L.Push(fn)
	return 1
}

func shortportPortOrService(L *lua.LState) int {
	return matcherFunc(L, collectInts(L.Get(1)), collectStrings(L.Get(2)))
}

// shortportVersionPortOrService mirrors nselib/shortport.lua's
// version_port_or_service(ports, services, protos, states, rarity): a
// factory (not a direct portrule like shortport.ssh) that additionally
// filters on protocol — tftp-version.nse's
// `shortport.version_port_or_service(69, "tftp", "udp")` must not also
// match a hypothetical TCP service on port 69. The real version also gates
// on port_is_excluded() and nmap.version_intensity() >= rarity; we don't
// track per-port exclusions (port_is_excluded is already a constant
// false — see the "nmap" preload above) and version_intensity() is a fixed
// 7, so that half of the real gate is effectively always satisfied — states
// filtering (open vs open|filtered) isn't applied either, a minor fidelity
// gap, not a functional one for the scripts that use this.
func shortportVersionPortOrService(L *lua.LState) int {
	ports := collectInts(L.Get(1))
	services := collectStrings(L.Get(2))
	protos := collectStrings(L.Get(3))
	fn := L.NewFunction(func(L *lua.LState) int {
		number, service := portFields(L, 2)
		matched := ports[number] || services[service]
		if matched && len(protos) > 0 {
			if t, ok := L.Get(2).(*lua.LTable); ok {
				proto := strings.ToLower(L.GetField(t, "protocol").String())
				matched = protos[proto]
			}
		}
		L.Push(lua.LBool(matched))
		return 1
	})
	L.Push(fn)
	return 1
}

func shortportPortNumber(L *lua.LState) int {
	return matcherFunc(L, collectInts(L.Get(1)), nil)
}

func shortportService(L *lua.LState) int {
	services := map[string]bool{}
	for i := 1; i <= L.GetTop(); i++ {
		for s := range collectStrings(L.Get(i)) {
			services[s] = true
		}
	}
	return matcherFunc(L, nil, services)
}

// --- http ----------------------------------------------------------------

func hostAddress(L *lua.LState, hostIdx int) string {
	if t, ok := L.Get(hostIdx).(*lua.LTable); ok {
		if name := L.GetField(t, "targetname").String(); name != "" {
			return name
		}
		return L.GetField(t, "ip").String()
	}
	return L.Get(hostIdx).String()
}

func portScheme(L *lua.LState, portIdx int) (scheme string, number int) {
	number, service := portFields(L, portIdx)
	scheme = "http"
	if strings.Contains(service, "https") || strings.Contains(service, "ssl") || number == 443 || number == 8443 {
		scheme = "https"
	}
	if t, ok := L.Get(portIdx).(*lua.LTable); ok {
		if ver, ok := L.GetField(t, "version").(*lua.LTable); ok {
			if L.GetField(ver, "service_tunnel").String() == "ssl" {
				scheme = "https"
			}
		}
	}
	if number == 0 {
		if scheme == "https" {
			number = 443
		} else {
			number = 80
		}
	}
	return
}

func (c *control) httpRequest(L *lua.LState, method string) int {
	host := hostAddress(L, 1)
	scheme, number := portScheme(L, 2)
	path := L.OptString(3, "/")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "http") {
		path = "/" + path
	}
	full := path
	if !strings.HasPrefix(path, "http") {
		full = fmt.Sprintf("%s://%s/%s", scheme, net.JoinHostPort(host, fmt.Sprint(number)), strings.TrimPrefix(path, "/"))
	}
	return c.doHTTP(L, method, full, "")
}

func (c *control) httpGet(L *lua.LState) int  { return c.httpRequest(L, http.MethodGet) }
func (c *control) httpHead(L *lua.LState) int { return c.httpRequest(L, http.MethodHead) }

func (c *control) httpPost(L *lua.LState) int {
	host := hostAddress(L, 1)
	scheme, number := portScheme(L, 2)
	path := L.OptString(3, "/")
	body := ""
	// http.post(host, port, path, options, ignored, postdata) in NSE varies;
	// accept a trailing string arg as the body.
	for i := L.GetTop(); i >= 4; i-- {
		if s, ok := L.Get(i).(lua.LString); ok {
			body = string(s)
			break
		}
	}
	full := fmt.Sprintf("%s://%s/%s", scheme, net.JoinHostPort(host, fmt.Sprint(number)), strings.TrimPrefix(path, "/"))
	return c.doHTTP(L, http.MethodPost, full, body)
}

func (c *control) httpGetURL(L *lua.LState) int {
	raw := L.CheckString(1)
	if !strings.HasPrefix(raw, "http") {
		raw = "http://" + raw
	}
	return c.doHTTP(L, http.MethodGet, raw, "")
}

func (c *control) doHTTP(L *lua.LState, method, rawURL, body string) int {
	resp := L.NewTable()
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		L.SetField(resp, "status", lua.LNil)
		L.Push(resp)
		return 1
	}
	req.Header.Set("User-Agent", "wscan-nse")
	r, err := c.do(req)
	if err != nil {
		L.SetField(resp, "status", lua.LNil)
		L.Push(resp)
		return 1
	}
	defer r.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	L.SetField(resp, "status", lua.LNumber(r.StatusCode))
	L.SetField(resp, "status_line", lua.LString(r.Status))
	L.SetField(resp, "body", lua.LString(string(data)))
	header := L.NewTable()
	for k := range r.Header {
		L.SetField(header, strings.ToLower(k), lua.LString(r.Header.Get(k)))
	}
	L.SetField(resp, "header", header)
	L.SetField(resp, "rawheader", header)
	if loc := r.Header.Get("Location"); loc != "" {
		arr := L.NewTable()
		arr.Append(lua.LString(loc))
		L.SetField(resp, "location", arr)
	}
	L.Push(resp)
	return 1
}

// --- comm ----------------------------------------------------------------

func (c *control) commExchange(L *lua.LState) int {
	host := hostAddress(L, 1)
	_, number := portScheme(L, 2)
	if n, _ := portFields(L, 2); n != 0 {
		number = n
	}
	data := L.OptString(3, "")
	conn, err := c.dial("tcp", net.JoinHostPort(host, fmt.Sprint(number)))
	if err != nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	defer conn.Close()
	c.setDeadline(conn)
	if data != "" {
		if _, err := conn.Write([]byte(data)); err != nil {
			L.Push(lua.LFalse)
			L.Push(lua.LString(err.Error()))
			return 2
		}
	}
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n == 0 {
		L.Push(lua.LFalse)
		L.Push(lua.LString("no response"))
		return 2
	}
	L.Push(lua.LTrue)
	L.Push(lua.LString(string(buf[:n])))
	return 2
}

func (c *control) commGetBanner(L *lua.LState) int {
	host := hostAddress(L, 1)
	number, _ := portFields(L, 2)
	if number == 0 {
		_, number = portScheme(L, 2)
	}
	conn, err := c.dial("tcp", net.JoinHostPort(host, fmt.Sprint(number)))
	if err != nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	defer conn.Close()
	c.setDeadline(conn)
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 {
		L.Push(lua.LFalse)
		L.Push(lua.LString("no banner"))
		return 2
	}
	L.Push(lua.LTrue)
	L.Push(lua.LString(string(buf[:n])))
	return 2
}

func (c *control) setDeadline(conn net.Conn) {
	deadline := time.Now().Add(c.timeout)
	if d, ok := c.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
}

// --- url -----------------------------------------------------------------

func urlEscape(L *lua.LState) int {
	L.Push(lua.LString(url.QueryEscape(L.CheckString(1))))
	return 1
}

func urlUnescape(L *lua.LState) int {
	s, err := url.QueryUnescape(L.CheckString(1))
	if err != nil {
		L.Push(lua.LString(L.CheckString(1)))
		return 1
	}
	L.Push(lua.LString(s))
	return 1
}

func urlAbsolute(L *lua.LState) int {
	base, err := url.Parse(L.CheckString(1))
	if err != nil {
		L.Push(lua.LString(L.CheckString(2)))
		return 1
	}
	ref, err := url.Parse(L.CheckString(2))
	if err != nil {
		L.Push(lua.LString(L.CheckString(2)))
		return 1
	}
	L.Push(lua.LString(base.ResolveReference(ref).String()))
	return 1
}

func urlParse(L *lua.LState) int {
	u, err := url.Parse(L.CheckString(1))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}
	t := L.NewTable()
	L.SetField(t, "scheme", lua.LString(u.Scheme))
	L.SetField(t, "host", lua.LString(u.Hostname()))
	L.SetField(t, "port", lua.LString(u.Port()))
	L.SetField(t, "path", lua.LString(u.Path))
	L.SetField(t, "query", lua.LString(u.RawQuery))
	L.Push(t)
	return 1
}

// Nmap's stateless port iterator: next scanned port after the supplied table.
func nmapGetPorts(L *lua.LState) int {
	host := L.CheckTable(1)
	previous := L.Get(2)
	protocol := L.OptString(3, "tcp")
	state := L.OptString(4, "open")
	ports, ok := L.GetField(host, "ports").(*lua.LTable)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	after := previous == lua.LNil
	var found lua.LValue = lua.LNil
	ports.ForEach(func(_ lua.LValue, value lua.LValue) {
		if found != lua.LNil {
			return
		}
		p, ok := value.(*lua.LTable)
		if !ok {
			return
		}
		if !after {
			if value == previous {
				after = true
			}
			return
		}
		if L.GetField(p, "protocol").String() == protocol && L.GetField(p, "state").String() == state {
			found = p
		}
	})
	L.Push(found)
	return 1
}
