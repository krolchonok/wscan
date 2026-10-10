package js

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func fakePGAudit(t *testing.T, passwordRequired bool, password string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				send := func(kind byte, body []byte) {
					frame := make([]byte, 5+len(body))
					frame[0] = kind
					binary.BigEndian.PutUint32(frame[1:5], uint32(4+len(body)))
					copy(frame[5:], body)
					c.Write(frame)
				}
				length := make([]byte, 4)
				if _, err := io.ReadFull(c, length); err != nil {
					return
				}
				size := binary.BigEndian.Uint32(length)
				if size < 4 || size > 65536 {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(size-4)); err != nil {
					return
				}
				if passwordRequired {
					send('R', []byte{0, 0, 0, 3})
					h := make([]byte, 5)
					if _, err := io.ReadFull(c, h); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(h[1:])
					if n < 4 || n > 65536 {
						return
					}
					p := make([]byte, n-4)
					if _, err := io.ReadFull(c, p); err != nil {
						return
					}
					if string(p) != password+"\x00" {
						send('E', []byte("SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00"))
						return
					}
				}
				send('R', []byte{0, 0, 0, 0})
				send('S', []byte("server_version\x0018.0\x00"))
				send('S', []byte("client_encoding\x00UTF8\x00"))
				send('Z', []byte{'I'})
				for {
					h := make([]byte, 5)
					if _, err := io.ReadFull(c, h); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(h[1:])
					if n < 4 || n > 65536 {
						return
					}
					if _, err := io.CopyN(io.Discard, c, int64(n-4)); err != nil {
						return
					}
					if h[0] == 'X' {
						return
					}
					send('I', nil)
					send('Z', []byte{'I'})
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}
func TestPGAuditSeparatesTrustFromPassword(t *testing.T) {
	c := NewPGClient(context.Background(), time.Second)
	for _, tc := range []struct {
		name      string
		requires  bool
		pass      string
		connected bool
		auth      string
	}{
		{"no-auth", false, "", true, "none"}, {"password-ignored", false, "postgres", true, "none"},
		{"correct", true, "postgres", true, "cleartext-password"}, {"wrong", true, "wrong", false, "cleartext-password"},
		{"empty-rejected", true, "", false, "cleartext-password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := fakePGAudit(t, tc.requires, "postgres")
			result, err := c.AuditConnect("127.0.0.1", port, "postgres", tc.pass)
			if err != nil || result.Connected != tc.connected || result.Authentication != tc.auth {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			ok, err := c.ConnectWithPassword("127.0.0.1", port, "postgres", tc.pass)
			want := tc.connected && tc.requires
			if err != nil || ok != want {
				t.Fatalf("password result=%v err=%v", ok, err)
			}
		})
	}
}

func TestPGAuditResultInJavaScript(t *testing.T) {
	port := fakePGAudit(t, false, "")
	result := Run(context.Background(), `var m=require('nuclei/postgres');var c=m.PGClient();var r=c.AuditConnect(Host,Port,'postgres','');r.connected && r.authentication === 'none';`, "", map[string]any{"Host": "127.0.0.1", "Port": port}, nil, "", time.Second)
	if result.Error != "" || !result.Success || result.Response != true {
		t.Fatalf("result=%+v", result)
	}
}
