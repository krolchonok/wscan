package nse

import (
	"context"
	"path/filepath"
	"testing"
)

// TestNBDInfoScriptLoads reproduces "nbd-info: ошибка загрузки: <string>
// line:152(column:29) near '[': syntax error" — the real cause was a
// transformLua53 bug (see TestTransformBitwiseAndThroughBracketIndexChain),
// not anything specific to NBD. A closed port (nothing listening) is enough
// to prove the script loads and runs its portrule/action cleanly.
func TestNBDInfoScriptLoads(t *testing.T) {
	lib, err := filepath.Abs("../../library")
	if err != nil {
		t.Fatal(err)
	}
	r := New(lib, Config{})
	scriptPath := filepath.Join(lib, "nmap", "scripts", "nbd-info.nse")
	_, _, err = r.Run(context.Background(), scriptPath, HostInfo{IP: "127.0.0.1"},
		[]PortInfo{{Number: 10809, Protocol: "tcp", State: "open", Service: "nbd"}})
	if err != nil {
		t.Fatalf("nbd-info.nse: %v", err)
	}
}
