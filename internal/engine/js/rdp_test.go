package js

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestIsRDPDetectsWindows10Signature reproduces "TypeError: Object has no
// member 'IsRDP'" (rdp-detect.yaml) — the module was a bare stub.
func TestIsRDPDetectsWindows10Signature(t *testing.T) {
	win10 := rdpOSSignatures["Windows 10"]
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, len(rdpNegotiationRequest))
		_, _ = c.Read(buf)
		_, _ = c.Write(win10)
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	resp, err := isRDP(context.Background(), "127.0.0.1", port, 5*time.Second)
	if err != nil {
		t.Fatalf("isRDP: %v", err)
	}
	if !resp.IsRDP || resp.OS != "Windows 10" {
		t.Fatalf("got %+v, want IsRDP=true OS=Windows 10", resp)
	}
}

// Negative: a non-RDP responder must error, not silently report IsRDP=false
// — matches real nuclei's own IsRDP contract (see rdp.go's doc comment).
func TestIsRDPNonRDPResponseErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, len(rdpNegotiationRequest))
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("not rdp at all"))
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	if _, err := isRDP(context.Background(), "127.0.0.1", port, 5*time.Second); err == nil {
		t.Fatal("expected an error for a non-RDP response")
	}
}
