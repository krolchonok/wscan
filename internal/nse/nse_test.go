package nse

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
)

func libraryDir(t *testing.T) string {
	t.Helper()
	for _, c := range []string{filepath.Join("..", "..", "library"), "library"} {
		if st, err := os.Stat(filepath.Join(c, "nmap", "nselib")); err == nil && st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("library/nmap/nselib not found")
	return ""
}

func serverPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	p, _ := strconv.Atoi(portStr)
	return p
}

func TestHTTPTitleScript(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><head><title>Go ahead and ScanMe!</title></head></html>"))
	}))
	defer srv.Close()
	port := serverPort(t, srv)

	lib := libraryDir(t)
	r := New(lib, Config{Timeout: 5 * time.Second})
	results, ran, err := r.Run(context.Background(), filepath.Join(lib, "nmap/scripts/http-title.nse"),
		HostInfo{IP: "127.0.0.1"},
		[]PortInfo{{Number: port, Protocol: "tcp", State: "open", Service: "http"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !ran {
		t.Fatal("script did not run")
	}
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(results), results)
	}
	if !strings.Contains(results[0].Output, "Go ahead and ScanMe!") {
		t.Errorf("unexpected output: %q", results[0].Output)
	}
}

func TestSMBScriptLibrariesAvailable(t *testing.T) {
	lib := libraryDir(t)
	src, err := os.ReadFile(filepath.Join(lib, "nmap/scripts/smb-os-discovery.nse"))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSource(src, lib); err != nil {
		t.Fatalf("smb-os-discovery should resolve nselib deps: %v", err)
	}
}

func TestTransformBitops(t *testing.T) {
	out := transformLua53(`local x = (a & 0xff) | (b << 2)`)
	for _, need := range []string{"bit.band", "bit.bor", "bit.lshift"} {
		if !strings.Contains(out, need) {
			t.Fatalf("missing %s in %s", need, out)
		}
	}
}

// TestTransformFloorDivAfterKeyword reproduces ftp-syst.nse's "syntax error
// near 'bit'": takeOperandLeft treated the Lua keyword "or" as a callable
// name immediately preceding a parenthesized group, so
// `not ok or (code % 100) // 10` got mis-rewritten (the "or" was absorbed
// into the bit.idiv(...) call target) instead of leaving "or" alone and only
// rewriting the "//" operands. Checks both that the transformed source still
// parses/executes AND that the floor-division result is numerically correct.
func TestTransformFloorDivAfterKeyword(t *testing.T) {
	lib := libraryDir(t)
	L := lua.NewState()
	defer L.Close()
	r := New(lib, Config{})
	ctrl := newControl(context.Background(), Config{Timeout: 5 * time.Second})
	defer ctrl.close()
	r.registerModules(L, ctrl, "test-floor-div")
	src := transformLua53(`
		local ok = false
		local code = 205
		if not ok or (code % 100) // 10 == 0 then
			x = 1
		else
			x = 2
		end
		y = (code % 100) // 10
	`)
	if err := L.DoString(src); err != nil {
		t.Fatalf("exec failed (transformed: %s): %v", src, err)
	}
	if x := L.GetGlobal("x"); x.(lua.LNumber) != 1 {
		t.Fatalf("got x=%v, want 1", x)
	}
	if y := L.GetGlobal("y"); y.(lua.LNumber) != 0 {
		t.Fatalf("got y=%v, want 0 (205%%100=5, 5//10=0)", y)
	}
}

// TestTransformBitwiseAndThroughBracketIndexChain reproduces nbd-info.nse's
// "syntax error near '['": takeOperandLeft's chain walker only absorbed a
// dotless index/call (`exports["(default)"]`) on the very first hop of the
// postfix chain it walks backward through. For
// `comm.exports["(default)"].hflags & x`, the chain has a DOT hop
// (".hflags") before the dotless bracket hop, so by the time the walker
// reached `exports[...]` it had already left the single-hop special case and
// fell into the dot-only loop, leaving "comm.exports" behind as plain text
// outside the bit.band(...) call it was rewritten into — unparseable output.
func TestTransformBitwiseAndThroughBracketIndexChain(t *testing.T) {
	lib := libraryDir(t)
	L := lua.NewState()
	defer L.Close()
	r := New(lib, Config{})
	ctrl := newControl(context.Background(), Config{Timeout: 5 * time.Second})
	defer ctrl.close()
	r.registerModules(L, ctrl, "test-bracket-chain")
	src := transformLua53(`
		local comm = {exports = {}}
		comm.exports["(default)"] = {hflags = 3}
		local nbd = {NBD = {handshake_flags = {FIXED_NEWSTYLE = 1}}}
		if comm.exports["(default)"].hflags & nbd.NBD.handshake_flags.FIXED_NEWSTYLE then
			x = 1
		else
			x = 2
		end
	`)
	if err := L.DoString(src); err != nil {
		t.Fatalf("exec failed (transformed: %s): %v", src, err)
	}
	if x := L.GetGlobal("x"); x.(lua.LNumber) != 1 {
		t.Fatalf("got x=%v, want 1 (3 & 1 == 1, truthy)", x)
	}
}

func TestStringPackRoundTrip(t *testing.T) {
	packed, err := stringPack(">I2B", []lua.LValue{lua.LNumber(0x0102), lua.LNumber(7)})
	if err != nil {
		t.Fatal(err)
	}
	if packed != "\x01\x02\x07" {
		t.Fatalf("pack=%q", packed)
	}
	vals, next, err := stringUnpack(">I2B", []byte(packed), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 2 || vals[0].(lua.LNumber) != 0x0102 || vals[1].(lua.LNumber) != 7 || next != 4 {
		t.Fatalf("unpack vals=%v next=%d", vals, next)
	}
}

func TestLoadSMBScriptsWithBitops(t *testing.T) {
	lib := libraryDir(t)
	scripts := []string{
		"smb-security-mode.nse",
		"smb2-capabilities.nse",
		"smb2-security-mode.nse",
		"smb-ls.nse",
		"smb-protocols.nse",
		"smb-os-discovery.nse",
	}
	Lsetup := func(scriptID string) (*lua.LState, *control) {
		L := lua.NewState()
		r := New(lib, Config{})
		ctrl := newControl(context.Background(), Config{Timeout: 5 * time.Second})
		r.registerModules(L, ctrl, scriptID)
		L.SetGlobal("SCRIPT_NAME", lua.LString(scriptID))
		L.SetGlobal("SCRIPT_TYPE", lua.LString("portrule"))
		return L, ctrl
	}
	for _, name := range scripts {
		src, err := os.ReadFile(filepath.Join(lib, "nmap/scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		id := strings.TrimSuffix(name, ".nse")
		L, ctrl := Lsetup(id)
		err = L.DoString(transformLua53(string(src)))
		ctrl.close()
		L.Close()
		if err != nil {
			t.Fatalf("%s load: %v", name, err)
		}
	}
}
