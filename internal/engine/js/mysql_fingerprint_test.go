package js

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mysqlTestGreeting() []byte {
	data := []byte("\x0a5.7.42\x00\x01\x00\x00\x00abcdefgh\x00")
	caps := uint32(1 | 4 | 512 | 2048 | 8192 | 32768 | 524288)
	low := make([]byte, 2)
	binary.LittleEndian.PutUint16(low, uint16(caps))
	data = append(data, low...)
	data = append(data, 33, 2, 0)
	binary.LittleEndian.PutUint16(low, uint16(caps>>16))
	data = append(data, low...)
	data = append(data, 21)
	data = append(data, make([]byte, 10)...)
	return append(data, []byte("ijklmnopqrst\x00mysql_native_password\x00")...)
}
func mysqlTestPacket(c net.Conn, seq byte, data []byte) {
	c.Write(append([]byte{byte(len(data)), byte(len(data) >> 8), byte(len(data) >> 16), seq}, data...))
}
func mysqlTestServer(t *testing.T, handle func(net.Conn)) (*net.TCPAddr, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	count := &atomic.Int32{}
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			count.Add(1)
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(time.Second)); handle(c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr), count
}
func TestFingerprintMySQLThroughJavaScript(t *testing.T) {
	addr, count := mysqlTestServer(t, func(c net.Conn) { mysqlTestPacket(c, 0, mysqlTestGreeting()) })
	r := Run(context.Background(), `var m=require("nuclei/mysql"); var c=m.MySQLClient(); Export(c.FingerprintMySQL(Host,Port));`, "", map[string]any{"Host": "127.0.0.1", "Port": addr.Port}, nil, "", time.Second)
	var fingerprint map[string]any
	jsonErr := json.Unmarshal([]byte(fmt.Sprint(r.Response)), &fingerprint)
	if r.Error != "" || !r.Success || jsonErr != nil || fingerprint["Version"] != "5.7.42" || fingerprint["TLS"] != true {
		t.Fatalf("%+v", r)
	}
	if count.Load() != 1 {
		t.Fatal("fingerprint made multiple connections")
	}
}
func TestFingerprintRejectsMalformedGreeting(t *testing.T) {
	for _, data := range [][]byte{{0xff}, {10, '5', '.', '7'}, {10, '5', 0}} {
		addr, _ := mysqlTestServer(t, func(c net.Conn) { mysqlTestPacket(c, 0, data) })
		if _, err := NewMySQLClient(context.Background(), time.Second).FingerprintMySQL("127.0.0.1", addr.Port); err == nil {
			t.Fatalf("accepted %v", data)
		}
	}
}
func TestMySQLBypassStopsNetworkError(t *testing.T) {
	addr, count := mysqlTestServer(t, func(c net.Conn) {})
	_, err := NewMySQLClient(context.Background(), time.Second).CheckAuthenticationBypass("127.0.0.1", addr.Port, "root", "wrong", "SHOW DATABASES")
	if err == nil || count.Load() != 1 {
		t.Fatalf("error=%v connections=%d", err, count.Load())
	}
}
func TestMySQLBypassOnlyRetriesAuthenticationRejection(t *testing.T) {
	for _, code := range []uint16{1040, 1045} {
		addr, count := mysqlTestServer(t, func(c net.Conn) {
			mysqlTestPacket(c, 0, mysqlTestGreeting())
			h := make([]byte, 4)
			if _, e := io.ReadFull(c, h); e != nil {
				return
			}
			n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
			if n > 65536 {
				return
			}
			if _, e := io.ReadFull(c, make([]byte, n)); e != nil {
				return
			}
			mysqlTestPacket(c, 2, append([]byte{0xff, byte(code), byte(code >> 8), '#', 'H', 'Y', '0', '0', '0'}, []byte("rejected")...))
		})
		_, err := NewMySQLClient(context.Background(), 100*time.Millisecond).CheckAuthenticationBypass("127.0.0.1", addr.Port, "root", "wrong", "SHOW DATABASES")
		if code == 1040 {
			if err == nil || count.Load() != 1 {
				t.Fatalf("non-auth error retried: %v %d", err, count.Load())
			}
		} else {
			if count.Load() < 2 {
				t.Fatal("auth rejection did not retry")
			}
			if err != nil && !strings.Contains(err.Error(), "не завершена") {
				t.Fatalf("unexpected: %v", err)
			}
		}
	}
}

func TestMySQLBypassRequiresPreviousPasswordRejection(t *testing.T) {
	for _, rejectFirst := range []bool{false, true} {
		var logins atomic.Int32
		addr, _ := mysqlTestServer(t, func(c net.Conn) {
			mysqlTestPacket(c, 0, mysqlTestGreeting())
			read := func() bool {
				h := make([]byte, 4)
				if _, e := io.ReadFull(c, h); e != nil {
					return false
				}
				n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
				if n > 65536 {
					return false
				}
				_, e := io.ReadFull(c, make([]byte, n))
				return e == nil
			}
			if !read() {
				return
			}
			attempt := logins.Add(1)
			if rejectFirst && attempt == 1 {
				mysqlTestPacket(c, 2, []byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'n', 'o'})
				return
			}
			mysqlTestPacket(c, 2, []byte{0, 0, 0, 2, 0, 0, 0})
			for read() {
				mysqlTestPacket(c, 1, []byte{0, 0, 0, 2, 0, 0, 0})
			}
		})
		result, err := NewMySQLClient(context.Background(), time.Second).CheckAuthenticationBypass("127.0.0.1", addr.Port, "root", "wrong", "SHOW DATABASES")
		if err != nil || result["Vulnerable"] != rejectFirst {
			t.Fatalf("rejectFirst=%t result=%v err=%v", rejectFirst, result, err)
		}
	}
}
