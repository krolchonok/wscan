package js

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

// fakeSMB2Negotiate builds a synthetic but wire-accurate SMB2 NEGOTIATE
// Response ([MS-SMB2] §2.2.4) carrying known securityMode/dialect/system
// times, so smbNegotiate's byte-offset decoding can be checked precisely
// against values we control.
func fakeSMB2NegotiateResponse(securityMode, dialect uint16, caps uint32, systemTime, serverStartTime uint64) []byte {
	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:2], 65) // StructureSize (not validated by our parser)
	binary.LittleEndian.PutUint16(body[2:4], securityMode)
	binary.LittleEndian.PutUint16(body[4:6], dialect)
	binary.LittleEndian.PutUint32(body[24:28], caps)
	binary.LittleEndian.PutUint64(body[40:48], systemTime)
	binary.LittleEndian.PutUint64(body[48:56], serverStartTime)

	header := make([]byte, 64)
	copy(header[0:4], []byte{0xfe, 'S', 'M', 'B'})

	pkt := make([]byte, 4+len(header)+len(body))
	binary.BigEndian.PutUint32(pkt[0:4], uint32(len(header)+len(body)))
	copy(pkt[4:], header)
	copy(pkt[4+len(header):], body)
	return pkt
}

// unixToFiletime is the inverse of filetimeToUnix, for building test fixtures.
func unixToFiletime(sec uint64) uint64 {
	const epochOffsetSeconds = 11644473600
	return (sec + epochOffsetSeconds) * 1e7
}

func fakeSMB2Listener(t *testing.T, resp []byte) int {
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
				buf := make([]byte, 4096)
				_, _ = c.Read(buf) // consume the client's NEGOTIATE request
				_, _ = c.Write(resp)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestSMBNegotiateDecodesRealSchema(t *testing.T) {
	wantSystemTime := uint64(1700000000)
	wantServerStartTime := uint64(1699000000)
	// SecurityMode 0x03 = signing enabled (bit0) + required (bit1).
	// Dialect 0x0311 = SMB 3.1.1. Caps 0x41 = DFS (0x01) + Encryption (0x40).
	resp := fakeSMB2NegotiateResponse(0x03, 0x0311, 0x41,
		unixToFiletime(wantSystemTime), unixToFiletime(wantServerStartTime))
	port := fakeSMB2Listener(t, resp)

	log, err := smbNegotiate(context.Background(), "127.0.0.1", port, 5*time.Second)
	if err != nil {
		t.Fatalf("smbNegotiate: %v", err)
	}
	if log.Version == nil || log.Version.VerString != "SMB 3.1.1" {
		t.Fatalf("Version.VerString = %+v, want SMB 3.1.1", log.Version)
	}
	if log.Capabilities == nil || !log.Capabilities.DFSSupport || !log.Capabilities.Encryption {
		t.Fatalf("Capabilities = %+v, want DFSSupport+Encryption", log.Capabilities)
	}
	if log.NegotiationLog == nil {
		t.Fatal("NegotiationLog is nil")
	}
	if log.NegotiationLog.SystemTime != uint32(wantSystemTime) {
		t.Fatalf("SystemTime = %d, want %d", log.NegotiationLog.SystemTime, wantSystemTime)
	}
	if log.NegotiationLog.ServerStartTime != uint32(wantServerStartTime) {
		t.Fatalf("ServerStartTime = %d, want %d", log.NegotiationLog.ServerStartTime, wantServerStartTime)
	}

	// ListSMBv2Metadata's SigningEnabled/SigningRequired come from the same
	// SecurityMode bits on the same NEGOTIATE response.
	c := &SMBClient{timeout: 5 * time.Second}
	c.ctx = context.Background()
	svc, err := c.ListSMBv2Metadata("127.0.0.1", port)
	if err != nil {
		t.Fatalf("ListSMBv2Metadata: %v", err)
	}
	if !svc.SigningEnabled || !svc.SigningRequired {
		t.Fatalf("ServiceSMB = %+v, want SigningEnabled+SigningRequired", svc)
	}
}

// TestSMBClientConstructorBothCallStyles pins the fix for "Value is not a
// constructor": real nuclei-templates/javascript/enumeration/smb/*.yaml use
// both `new m.SMBClient()` and `m.SMBClient()`.
func TestSMBClientConstructorBothCallStyles(t *testing.T) {
	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", false))
	_ = vm.Set("require", func(call goja.FunctionCall) goja.Value {
		return smbModule(vm, context.Background(), 5*time.Second)
	})
	for _, code := range []string{
		`var m = require("nuclei/smb"); var c = new m.SMBClient(); typeof c.ConnectSMBInfoMode`,
		`var m = require("nuclei/smb"); var c = m.SMBClient(); typeof c.ConnectSMBInfoMode`,
	} {
		v, err := vm.RunString(code)
		if err != nil {
			t.Fatalf("%s: %v", code, err)
		}
		if v.String() != "function" {
			t.Fatalf("%s: got %v, want function", code, v)
		}
	}
}

// TestToJSONMatchesColonSpaceConvention exercises the real to_json global
// (runtime.go, same package) through Run — real templates rely on its exact
// output shape, e.g. smb-v1-supported.yaml's word matcher looks for the
// literal substring `"SupportV1": true`, which JSON.stringify's compact
// `"SupportV1":true` (no space) would not satisfy.
func TestToJSONMatchesColonSpaceConvention(t *testing.T) {
	res := Run(context.Background(), `to_json({SupportV1: true})`, "", nil, nil, "", 5*time.Second)
	if res.Error != "" {
		t.Fatalf("to_json errored: %s", res.Error)
	}
	got, ok := res.Response.(string)
	if !ok {
		t.Fatalf("to_json response is %T, want string", res.Response)
	}
	if want := `"SupportV1": true`; !strings.Contains(got, want) {
		t.Fatalf("to_json output %q does not contain %q", got, want)
	}
}

// TestProcessExitStopsCleanly reproduces "Ошибка проверки: ...: javascript:
// ReferenceError: process is not defined" (samba-detect.yaml's
// `process.exit(1)` idiom for "not a match, stop here").
func TestProcessExitStopsCleanly(t *testing.T) {
	res := Run(context.Background(), `
		var ran = false;
		process.exit(1);
		ran = true; // must never execute
	`, "", nil, nil, "", 5*time.Second)
	if res.Error != "" {
		t.Fatalf("process.exit must not surface as an error, got %q", res.Error)
	}
	if res.Success {
		t.Fatal("process.exit must produce Success=false (no match)")
	}
}

// TestBytesBufferConstructorBothCallStyles pins the fix for "Value is not a
// constructor" at `new bytes.Buffer()` (CVE-2024-51978.yaml's
// generateDefaultPassword helper) — real templates use both `new
// bytes.Buffer()` and `bytes.NewBuffer()`.
func TestBytesBufferConstructorBothCallStyles(t *testing.T) {
	res := Run(context.Background(), `
		const b1 = new bytes.Buffer();
		b1.Write([1,2,3]);
		const b2 = bytes.NewBuffer();
		b2.WriteString("ab");
		b1.Hex() + "|" + b2.Hex();
	`, "", nil, nil, "", 5*time.Second)
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
	got, _ := res.Response.(string)
	if want := "010203|6162"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
