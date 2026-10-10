package js

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// fakeNoAuthVNCServer implements just enough of RFB 3.3 (RFC 6143 §7) with
// security type 1 (None) to exercise go-vnc's real handshake end to end:
// version exchange, the 4-byte security-type announcement, ClientInit, and
// a minimal ServerInit. No DES/VNC-Auth involved — this is exactly
// unauth-vnc-server-detect.yaml's scenario (server requires no password at
// all, so Connect() with any password text must still return true).
func fakeNoAuthVNCServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("RFB 003.003\n"))
				buf := make([]byte, 12)
				if _, err := readFull(c, buf); err != nil {
					return
				}
				secType := make([]byte, 4)
				binary.BigEndian.PutUint32(secType, 1) // None
				if _, err := c.Write(secType); err != nil {
					return
				}
				clientInit := make([]byte, 1)
				if _, err := readFull(c, clientInit); err != nil {
					return
				}
				// ServerInit: width(2) height(2) pixelformat(16) namelen(4)=0
				serverInit := make([]byte, 24)
				binary.BigEndian.PutUint16(serverInit[0:2], 800)
				binary.BigEndian.PutUint16(serverInit[2:4], 600)
				serverInit[4] = 32 // bits-per-pixel
				serverInit[5] = 24 // depth
				if _, err := c.Write(serverInit); err != nil {
					return
				}
				// The real client still sends SetEncodings/SetPixelFormat
				// before Connect() returns — keep the connection open and
				// discard whatever arrives instead of closing immediately,
				// or those writes see a broken pipe and Connect() errors.
				discard := make([]byte, 4096)
				for {
					if _, err := c.Read(discard); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// TestVNCConnectNoAuthSucceeds pins the fix for "TypeError: Value is not an
// object: undefined" (require("nuclei/vnc") was a stub with zero methods):
// a real RFB handshake against a server offering no authentication must
// report success regardless of the password text passed in — exactly what
// unauth-vnc-server-detect.yaml relies on.
func TestVNCConnectNoAuthSucceeds(t *testing.T) {
	port := fakeNoAuthVNCServer(t)
	c := &VNCClient{ctx: context.Background(), timeout: 5 * time.Second}
	ok, err := c.Connect("127.0.0.1", port, " ")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true when the server requires no authentication")
	}
}

// Negative: nothing listening must be a real error, not a quiet false — the
// isVNCAuthError substring heuristic must not swallow a genuine connection
// failure.
func TestVNCConnectRefusedIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	c := &VNCClient{ctx: context.Background(), timeout: 2 * time.Second}
	ok, err := c.Connect("127.0.0.1", port, "x")
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if ok {
		t.Fatal("expected ok=false on error")
	}
}
