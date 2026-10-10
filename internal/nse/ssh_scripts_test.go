package nse

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// TestScriptsWithPreviouslyMissingNativeFunctionsLoad reproduces the
// real-world run errors "нет portrule/hostrule" (ssh-hostkey,
// ssh-auth-methods, ssh-brute, ssh2-enum-algos — all use
// `portrule = shortport.ssh`, which this engine's native shortport module
// didn't implement at all), "ошибка загрузки: attempt to call a
// non-function object" (ssh-publickey-acceptance's top-level
// `nmap.fetchfile(...)`, http-fetch's `lfs.get_path_separator()` — neither
// had a native implementation), each from a genuinely missing stub function,
// not a real protocol/target issue. A closed port (nothing is listening) is
// enough to prove each script at least loads and runs its portrule/action
// cleanly — it doesn't need a real server to find out it isn't vulnerable.
func TestScriptsWithPreviouslyMissingNativeFunctionsLoad(t *testing.T) {
	lib, err := filepath.Abs("../../library")
	if err != nil {
		t.Fatal(err)
	}
	scripts := []string{
		"ssh-hostkey.nse",
		"ssh-auth-methods.nse",
		"ssh-brute.nse",
		"ssh2-enum-algos.nse",
		"ssh-publickey-acceptance.nse",
		// Unrelated to ssh itself, but the same bug class (a missing native
		// stub function broke loading entirely) — lfs.get_path_separator()
		// was never implemented at all.
		"http-fetch.nse",
	}
	r := New(lib, Config{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	number := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	port := PortInfo{Number: number, Protocol: "tcp", State: "open", Service: "ssh"}
	for _, name := range scripts {
		name := name
		t.Run(name, func(t *testing.T) {
			scriptPath := filepath.Join(lib, "nmap", "scripts", name)
			_, _, err := r.Run(context.Background(), scriptPath, HostInfo{IP: "127.0.0.1"}, []PortInfo{port})
			// Previously Run silently discarded this runtime failure. Loading
			// the script works, but brute's scheduler is not implemented.
			if name == "ssh-brute.nse" {
				if err == nil || !strings.Contains(err.Error(), "NSE coroutine scheduler is not supported") {
					t.Fatalf("expected explicit scheduler error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
	}
}
