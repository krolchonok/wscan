package nse

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	lua "github.com/yuin/gopher-lua"
)

// Go-backed modules take priority over nselib/*.lua via package.preload.
var goModules = map[string]bool{
	"nmap": true, "stdnse": true, "shortport": true,
	"http": true, "comm": true, "url": true,
	"openssl": true, "unittest": true, "lfs": true,
	"lpeg": true, "nmapdb": true, "libssh2": true, "utf8": true,
}

// Builtin Lua libraries that require() resolves without our searcher.
var luaBuiltins = map[string]bool{
	"string": true, "table": true, "math": true, "io": true, "os": true,
	"coroutine": true, "package": true, "debug": true, "bit32": true, "utf8": true,
	"_G": true,
}

var requireRE = regexp.MustCompile(`(?m)require\s*(?:\(?\s*)['"]([A-Za-z0-9_./-]+)['"]`)

var (
	nselibTransformCache sync.Map // abs path -> transformed source string
)

func (r *Runner) nselibDir() string {
	if r.libraryDir == "" {
		return ""
	}
	return filepath.Join(r.libraryDir, "nmap", "nselib")
}

// registerNselibLoader installs a package.loaders searcher that serves
// transformed nselib Lua modules (Lua 5.3 → gopher-lua).
func (r *Runner) registerNselibLoader(L *lua.LState) {
	dir := r.nselibDir()
	if dir == "" {
		return
	}
	searcher := L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)
		if goModules[name] || luaBuiltins[name] {
			L.Push(lua.LString("\n\tno nselib module '" + name + "' (builtin/preload)"))
			return 1
		}
		path, err := resolveNselibPath(dir, name)
		if err != nil {
			L.Push(lua.LString("\n\tno file '" + name + "' in nselib"))
			return 1
		}
		src, err := loadTransformedNselib(path)
		if err != nil {
			L.Push(lua.LString(fmt.Sprintf("\n\terror loading '%s': %v", name, err)))
			return 1
		}
		fn, err := L.LoadString(src)
		if err != nil {
			L.RaiseError("%s: %v", name, err)
			return 0
		}
		L.Push(fn)
		L.Push(lua.LString(path))
		return 2
	})
	pkg := L.GetGlobal("package")
	loaders, ok := L.GetField(pkg, "loaders").(*lua.LTable)
	if !ok {
		return
	}
	// Insert after preload searcher (index 1) so package.preload still wins.
	n := loaders.Len()
	for i := n + 1; i >= 3; i-- {
		loaders.RawSetInt(i, loaders.RawGetInt(i-1))
	}
	loaders.RawSetInt(2, searcher)
}

func resolveNselibPath(dir, name string) (string, error) {
	name = strings.ReplaceAll(name, ".", string(filepath.Separator))
	candidates := []string{
		filepath.Join(dir, name+".lua"),
		filepath.Join(dir, name, "init.lua"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func loadTransformedNselib(path string) (string, error) {
	if v, ok := nselibTransformCache.Load(path); ok {
		return v.(string), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Two unrelated gopher-lua (Lua 5.1) vs. real nmap (Lua 5.2+) gaps, both
	// fixed by code prepended before anything the module itself does:
	//
	// 1. Most nselib modules isolate their globals with the standard idiom
	//    "_ENV = require 'stdnse'.module(name)" (no "local": it rebinds
	//    whatever _ENV already is) followed by "return _ENV" at the end to
	//    export what they defined. A rare few (e.g. libssh2-utility.lua)
	//    skip the assignment and just do bare "return _ENV", relying on
	//    Lua 5.2+'s implicit per-chunk _ENV upvalue that exists without the
	//    module ever assigning it. gopher-lua has no such upvalue: an
	//    unassigned "_ENV" is simply an undefined global (nil), so
	//    "return _ENV" returns nil, and require() then substitutes the Lua
	//    sentinel `true` for a nil module return — every caller's
	//    `mod.fn()` then fails with "non-table object(boolean)". Declaring
	//    a local _ENV up front covers that rare case; a module that assigns
	//    its own "_ENV = ..." (handled by envAssignRE below) just rebinds
	//    this same local — harmless either way.
	//
	// 2. transformLua53 rewrites Lua 5.3's native bitwise operators
	//    (a>>2, a&0x3f, ...) — which need no name resolution, they're
	//    language syntax — into calls against a Go-provided "bit" table
	//    (bit.rshift(a,2), ...), which DOES need a "bit" global to resolve.
	//    Any module using the isolation idiom above runs its functions
	//    with _ENV swapped to stdnse.module()'s bare table (no fallback to
	//    the real globals, matching real nmap: modules are expected to
	//    capture everything they need as locals before reassigning _ENV).
	//    Since the original source never referenced "bit" at all, it never
	//    did that, so our rewrite's "bit" reference resolves to nil the
	//    first time such a module actually calls one of its own bit-using
	//    functions — e.g. base64.lua's enc() dies on "bit.band" this way.
	//    A "local bit = bit" captured here, before any module's own _ENV
	//    swap, is a true Lua upvalue: lexical closures find it regardless
	//    of which table is active as _ENV later, so it survives the swap.
	const envPrologue = "local bit = bit; local _ENV = setmetatable({}, {__index = _G}); setfenv(1, _ENV);\n"
	src := envPrologue + transformLua53(string(raw))
	nselibTransformCache.Store(path, src)
	return src, nil
}

// checkRequiresAvailable walks require() deps and ensures each resolves to a
// Go module, Lua builtin, stub, or nselib file.
func (r *Runner) checkRequiresAvailable(source []byte) error {
	dir := r.nselibDir()
	seen := map[string]bool{}
	var walk func(src string) error
	walk = func(src string) error {
		for _, m := range requireRE.FindAllStringSubmatch(src, -1) {
			name := m[1]
			if seen[name] || luaBuiltins[name] || goModules[name] {
				continue
			}
			seen[name] = true
			if dir == "" {
				return fmt.Errorf("module '%s' not found", name)
			}
			path, err := resolveNselibPath(dir, name)
			if err != nil {
				return fmt.Errorf("module '%s' not found", name)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("module '%s' not found", name)
			}
			if err := walk(string(raw)); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(string(source))
}
