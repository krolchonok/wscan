package engine

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"testing"

	"wscan/internal/domain"
)

// withJSPort records the fake listener port for runMSF and direct tests.
// Tests must also put that port in the selected scan target: the engine
// intentionally ignores template Port when it binds to a selected service.
func withJSPort(tmpl domain.Template, port int) domain.Template {
	out := tmpl
	out.JavaScript = append([]domain.JavaScriptRequest(nil), tmpl.JavaScript...)
	for i := range out.JavaScript {
		args := make(map[string]any, len(out.JavaScript[i].Args)+1)
		for k, v := range out.JavaScript[i].Args {
			args[k] = v
		}
		args["Port"] = port
		out.JavaScript[i].Args = args
	}
	return out
}

// fakeUDPListener answers each datagram with handler's reply (nil => no
// reply), for testing udp: true msf-scanner templates end to end.
func fakeUDPListener(t *testing.T, handler func(data []byte) []byte) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := handler(append([]byte(nil), buf[:n]...)); resp != nil {
				_, _ = conn.WriteToUDP(resp, addr)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// fakeRedisListener is a minimal RESP responder: whatever the client sends
// (our native client only ever sends one INFO/AUTH command per connection
// here), it replies once with a single bulk string and closes.
func fakeRedisListener(t *testing.T, bulk string) int {
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
				buf := make([]byte, 512)
				_, _ = c.Read(buf) // consume the RESP-encoded INFO command
				_, _ = c.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(bulk), bulk)))
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestMSFGeneratedSSHVersionBanner covers the ssh_version.rb PROBE_OVERRIDES
// entry: a plain banner grab, since SSH servers send their ident line
// unsolicited right after the TCP handshake (RFC 4253 §4.2).
func TestMSFGeneratedSSHVersionBanner(t *testing.T) {
	tmpl := loadMSFTemplate(t, "msf-ssh-ssh-version.yaml")
	port := fakeListener(t, []byte("SSH-2.0-OpenSSH_9.6\r\n"))
	res := runMSF(t, withListenerPort(tmpl, port))
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
}

// TestMSFGeneratedRedisServerInfo covers the redis_server.rb JS_OVERRIDES
// entry end to end: the native RESP client (internal/engine/js/redis.go)
// sends INFO and the javascript: matchers check the real response text.
func TestMSFGeneratedRedisServerInfo(t *testing.T) {
	tmpl := loadMSFTemplate(t, "msf-redis-redis-server.yaml")
	port := fakeRedisListener(t, "# Server\r\nredis_version:7.4.0\r\nredis_mode:standalone\r\n")
	res := runMSF(t, withJSPort(tmpl, port))
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
}

// Negative: a bulk reply without "redis_version" (e.g. a non-Redis service
// that happens to answer on the port) must not match.
func TestMSFGeneratedRedisServerInfoNegative(t *testing.T) {
	tmpl := loadMSFTemplate(t, "msf-redis-redis-server.yaml")
	port := fakeRedisListener(t, "not a redis server")
	res := runMSF(t, withJSPort(tmpl, port))
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(res.Findings))
	}
}

// TestMSFGeneratedMemcachedUDPVersion covers the new Auxiliary::UDPScanner
// codegen path (extract_build_probe / pack_mixed): it both exercises the
// udp: true template end to end and pins the exact probe bytes memcached's
// build_probe would send (rand() folded to 0 — the module never validates
// the echoed request id, only the "VERSION ..." text).
func TestMSFGeneratedMemcachedUDPVersion(t *testing.T) {
	tmpl := loadMSFTemplate(t, "msf-memcached-memcached-udp-version.yaml")
	var gotProbe []byte
	port := fakeUDPListener(t, func(data []byte) []byte {
		gotProbe = data
		return []byte("VERSION 1.6.21\r\n")
	})
	res := runMSF(t, withListenerPort(tmpl, port))
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
	wantProbe, err := hex.DecodeString("000000000001000076657273696f6e0d0a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotProbe, wantProbe) {
		t.Fatalf("probe mismatch:\n got  % x\n want % x", gotProbe, wantProbe)
	}
}
