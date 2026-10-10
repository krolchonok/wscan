package engine

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"wscan/internal/domain"
	tpl "wscan/internal/template"
)

func msfScannerDir(t *testing.T) string {
	t.Helper()
	for _, c := range []string{
		filepath.Join("..", "..", "library", "nuclei-templates", "custom", "msf-scanner"),
		filepath.Join("library", "nuclei-templates", "custom", "msf-scanner"),
	} {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("library/nuclei-templates/custom/msf-scanner not found")
	return ""
}

func loadMSFTemplate(t *testing.T, name string) domain.Template {
	t.Helper()
	path := filepath.Join(msfScannerDir(t), name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	tm, err := tpl.ForExecution(raw, "custom/msf-scanner/"+name)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if !tm.Compatible {
		t.Fatalf("%s not compatible: %v", name, tm.Unsupported)
	}
	return tm
}

func withListenerPort(tmpl domain.Template, port int) domain.Template {
	out := tmpl
	out.TCP = append([]domain.TCPRequest(nil), tmpl.TCP...)
	for i := range out.TCP {
		out.TCP[i].Port = domain.IntList{port}
	}
	return out
}

func fakeListener(t *testing.T, resp []byte) int {
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
			_, _ = c.Write(resp)
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func runMSF(t *testing.T, tmpl domain.Template) *Result {
	t.Helper()
	target := "127.0.0.1"
	// Synthetic listeners are explicit scan targets; template args must not
	// override the selected service in production.
	for _, request := range tmpl.JavaScript {
		if port, ok := request.Args["Port"]; ok {
			target = fmt.Sprintf("http://127.0.0.1:%v", port)
			break
		}
	}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{target}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return &res
}

// TestMSFGeneratedTemplatesCompatible loads every auto-generated MSF scanner
// yaml and checks the native parser marks it Compatible. This is the batch
// gate for codegen — no per-module hand tests.
func TestMSFGeneratedTemplatesCompatible(t *testing.T) {
	dir := msfScannerDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		n++
		_ = loadMSFTemplate(t, e.Name())
	}
	if n < 20 {
		t.Fatalf("expected >=20 generated msf templates, got %d", n)
	}
	t.Logf("compatible msf-scanner templates: %d", n)
}

func TestMSFGoldenPOP3Banner(t *testing.T) {
	tmpl := loadMSFTemplate(t, "msf-pop3-pop3-version.yaml")
	port := fakeListener(t, []byte("+OK POP3 ready <1234.5678@mail.example.com>\r\n"))
	res := runMSF(t, withListenerPort(tmpl, port))
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
}

func TestMSFGoldenModbusDetect(t *testing.T) {
	tmpl := loadMSFTemplate(t, "msf-scada-modbusdetect.yaml")
	resp, err := hex.DecodeString("2100000000050104020001")
	if err != nil {
		t.Fatal(err)
	}
	port := fakeListener(t, resp)
	res := runMSF(t, withListenerPort(tmpl, port))
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}

	// Negative: wrong transaction/protocol id prefix.
	bad, _ := hex.DecodeString("ffeeddcc00050104020001")
	port2 := fakeListener(t, bad)
	res2 := runMSF(t, withListenerPort(tmpl, port2))
	if len(res2.Findings) != 0 {
		t.Fatalf("expected 0 findings on wrong header, got %d", len(res2.Findings))
	}
}

func TestMSFGoldenSercommBackdoor(t *testing.T) {
	tmpl := loadMSFTemplate(t, "msf-misc-sercomm-backdoor-scanner.yaml")
	port := fakeListener(t, []byte("MMcS\x00\x00\x00\x00"))
	res := runMSF(t, withListenerPort(tmpl, port))
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding (MMcS), got %d errs=%v", len(res.Findings), res.Errors)
	}

	port2 := fakeListener(t, []byte("ScMM\x00\x00\x00\x00"))
	res2 := runMSF(t, withListenerPort(tmpl, port2))
	if len(res2.Findings) != 1 {
		t.Fatalf("expected 1 finding (ScMM), got %d errs=%v", len(res2.Findings), res.Errors)
	}

	port3 := fakeListener(t, []byte("nope"))
	res3 := runMSF(t, withListenerPort(tmpl, port3))
	if len(res3.Findings) != 0 {
		t.Fatalf("expected 0 findings for non-signature, got %d", len(res3.Findings))
	}
}

func TestMSFGoldenClamAVVersion(t *testing.T) {
	tmpl := loadMSFTemplate(t, "msf-misc-clamav-control.yaml")
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
			line, _ := bufio.NewReader(c).ReadString('\n')
			if line == "VERSION\n" {
				_, _ = c.Write([]byte("ClamAV 0.103.0/26000/Mon Jan  1 00:00:00 2024\n"))
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	res := runMSF(t, withListenerPort(tmpl, port))
	if len(res.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
}
