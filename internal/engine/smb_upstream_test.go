package engine

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wscan/internal/domain"
	tpl "wscan/internal/template"
)

// These tests load the real, unmodified upstream templates that a live
// wscan run reported failing on (javascript: ReferenceError/TypeError —
// "to_json is not defined", "Value is not a constructor", "Cannot read
// property 'SystemTime' of undefined") and prove each bug class is fixed by
// actually running the exact template against a synthetic SMB2 server,
// instead of just re-asserting internal/engine/js's own unit tests.

// upstreamSMBTemplateDir resolves a directory under
// library/nuclei-templates/javascript/<sub> (sub is the full relative path,
// e.g. "enumeration/smb" or "cves/2026").
func upstreamSMBTemplateDir(t *testing.T, sub string) string {
	t.Helper()
	for _, c := range []string{
		filepath.Join("..", "..", "library", "nuclei-templates", "javascript", sub),
		filepath.Join("library", "nuclei-templates", "javascript", sub),
	} {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatalf("library/nuclei-templates/javascript/%s not found", sub)
	return ""
}

func loadUpstreamSMBTemplate(t *testing.T, sub, name string) domain.Template {
	t.Helper()
	path := filepath.Join(upstreamSMBTemplateDir(t, sub), name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	tm, err := tpl.ForExecution(raw, "javascript/"+sub+"/"+name)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if !tm.Compatible {
		t.Fatalf("%s not compatible: %v", name, tm.Unsupported)
	}
	return tm
}

// fakeSMB2NegotiateResponsePacket is the same wire-accurate NEGOTIATE
// Response builder as internal/engine/js's test (duplicated rather than
// exported across package boundaries for a handful of lines).
func fakeSMB2NegotiateResponsePacket(securityMode, dialect uint16, caps uint32, systemTime, serverStartTime uint64) []byte {
	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:2], 65)
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

func unixToFiletimeForTest(sec uint64) uint64 {
	const epochOffsetSeconds = 11644473600
	return (sec + epochOffsetSeconds) * 1e7
}

func fakeSMB2ServerForUpstreamTest(t *testing.T, resp []byte) int {
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
				_, _ = c.Read(buf)
				_, _ = c.Write(resp)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestUpstreamSMBVersionDetectUsesNewConstructor reproduces
// "Ошибка проверки: smb-version-detect: javascript: TypeError: Value is not
// a constructor" — the template uses `new m.SMBClient()`.
func TestUpstreamSMBVersionDetectUsesNewConstructor(t *testing.T) {
	tmpl := loadUpstreamSMBTemplate(t, "enumeration/smb", "smb-version-detect.yaml")
	resp := fakeSMB2NegotiateResponsePacket(0x01, 0x0311, 0, unixToFiletimeForTest(1700000000), 0)
	port := fakeSMB2ServerForUpstreamTest(t, resp)
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{fmt.Sprintf("http://127.0.0.1:%d", port)}}, []domain.Template{withJSPort(tmpl, port)})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range res.Errors {
		t.Errorf("unexpected error: %s", e)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
}

// TestUpstreamSMBV1SupportedUsesToJSON reproduces "Ошибка проверки:
// smb-v1-supported: javascript: ReferenceError: to_json is not defined" —
// the template's last statement is `to_json(response);` and its word
// matcher looks for the literal `"SupportV1": true`.
func TestUpstreamSMBV1SupportedUsesToJSON(t *testing.T) {
	tmpl := loadUpstreamSMBTemplate(t, "enumeration/smb", "smb-v1-supported.yaml")
	// Non-"\xfeSMB" first 4 bytes of the header → our client's SMB1 fallback
	// path, which sets SupportV1: true. Real SMB1 negotiate responses run
	// well past our 72-byte minimum; pad to match.
	resp := make([]byte, 80)
	copy(resp[4:8], []byte{0xff, 'S', 'M', 'B'})
	port := fakeSMB2ServerForUpstreamTest(t, resp)
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{fmt.Sprintf("http://127.0.0.1:%d", port)}}, []domain.Template{withJSPort(tmpl, port)})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range res.Errors {
		t.Errorf("unexpected error: %s", e)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
}

// TestUpstreamSMB2ServerTimeReadsNegotiationLog reproduces "Ошибка проверки:
// smb2-server-time: javascript: TypeError: Cannot read property
// 'SystemTime' of undefined" — the template reads
// response.NegotiationLog.SystemTime / .ServerStartTime.
func TestUpstreamSMB2ServerTimeReadsNegotiationLog(t *testing.T) {
	tmpl := loadUpstreamSMBTemplate(t, "enumeration/smb", "smb2-server-time.yaml")
	resp := fakeSMB2NegotiateResponsePacket(0x01, 0x0311, 0,
		unixToFiletimeForTest(1700000000), unixToFiletimeForTest(1699000000))
	port := fakeSMB2ServerForUpstreamTest(t, resp)
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{fmt.Sprintf("http://127.0.0.1:%d", port)}}, []domain.Template{withJSPort(tmpl, port)})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range res.Errors {
		t.Errorf("unexpected error: %s", e)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
}

// TestUpstreamSMBConnectInfoTemplatesDontCrash sweeps every remaining
// upstream require("nuclei/smb") template that only calls
// ConnectSMBInfoMode/ListSMBv2Metadata (no session/share I/O, which needs a
// real SMB partner to exercise meaningfully) and asserts none of them hit
// the three reported bug classes — ReferenceError (to_json), "is not a
// constructor" (new), or a nil-dereference reading an expected nested field
// — against a generic fake SMB2 server. They may still legitimately find
// nothing (e.g. ntlm-info.yaml needs NTLM data this engine doesn't parse
// yet, documented in smb.go) — that's a quiet non-match, not a crash.
func TestUpstreamSMBConnectInfoTemplatesDontCrash(t *testing.T) {
	cases := []struct{ sub, name string }{
		{"enumeration/smb", "ntlm-info.yaml"},
		{"enumeration/smb", "smb-enum-domains.yaml"},
		{"enumeration/smb", "smb-enum.yaml"},
		{"enumeration/smb", "smb-os-detect.yaml"},
		{"enumeration/smb", "smb2-capabilities.yaml"},
		{"detection", "samba-detect.yaml"},
		{"cves/2026", "CVE-2026-4480.yaml"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tmpl := loadUpstreamSMBTemplate(t, tc.sub, tc.name)
			resp := fakeSMB2NegotiateResponsePacket(0x01, 0x0311, 0x41,
				unixToFiletimeForTest(1700000000), unixToFiletimeForTest(1699000000))
			port := fakeSMB2ServerForUpstreamTest(t, resp)
			e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
			res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{fmt.Sprintf("http://127.0.0.1:%d", port)}}, []domain.Template{withJSPort(tmpl, port)})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			for _, e := range res.Errors {
				for _, bad := range []string{"ReferenceError", "is not a constructor", "Cannot read property"} {
					if strings.Contains(e, bad) {
						t.Fatalf("%s: hit reported bug class %q: %s", tc.name, bad, e)
					}
				}
			}
		})
	}
}

// TestUpstreamSMBSigningReadsSecurityMode covers smb-signing.yaml, which
// needs ListSMBv2Metadata's ServiceSMB.SigningEnabled/SigningRequired.
func TestUpstreamSMBSigningReadsSecurityMode(t *testing.T) {
	tmpl := loadUpstreamSMBTemplate(t, "misconfiguration/smb", "smb-signing.yaml")
	// SecurityMode 0x01 = signing enabled, not required.
	resp := fakeSMB2NegotiateResponsePacket(0x01, 0x0311, 0, 0, 0)
	port := fakeSMB2ServerForUpstreamTest(t, resp)
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{fmt.Sprintf("http://127.0.0.1:%d", port)}}, []domain.Template{withJSPort(tmpl, port)})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range res.Errors {
		t.Errorf("unexpected error: %s", e)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
}
