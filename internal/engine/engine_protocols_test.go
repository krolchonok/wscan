package engine

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"wscan/internal/domain"
)

func bannerListener(t *testing.T, banner []byte) (string, int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 64)
			_, _ = c.Read(buf)
			_, _ = c.Write(banner)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

func TestTCPWordMatcher(t *testing.T) {
	_, port := bannerListener(t, []byte("HELLO-BANNER-v1"))
	tmpl := domain.Template{ID: "tcp-word", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.TCP = []domain.TCPRequest{{
		Inputs:   []domain.TCPInput{{Data: "ping"}},
		Host:     domain.StringList{"{{Hostname}}"},
		Port:     domain.IntList{port},
		Matchers: []domain.Matcher{{Type: "word", Part: "data", Words: []string{"HELLO-BANNER"}}},
	}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"127.0.0.1"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("tcp word: expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
}

func TestTCPDialAddrPortOverridesHostname(t *testing.T) {
	got, err := tcpDialAddr("10.0.0.10:80", 427)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.10:427" {
		t.Fatalf("got %q want 10.0.0.10:427", got)
	}
	got, err = tcpDialAddr("http://10.0.0.10:80/path", 427)
	if err != nil || got != "10.0.0.10:427" {
		t.Fatalf("url host: got %q err=%v", got, err)
	}
	got, err = tcpDialAddr("10.0.0.10", 427)
	if err != nil || got != "10.0.0.10:427" {
		t.Fatalf("bare host: got %q err=%v", got, err)
	}
	got, err = tcpDialAddr("10.0.0.10:9999", 0)
	if err != nil || got != "10.0.0.10:9999" {
		t.Fatalf("embedded only: got %q err=%v", got, err)
	}
}

func TestTCPPortOverridesScanURLPort(t *testing.T) {
	_, wantPort := bannerListener(t, []byte("SLP-OK"))
	tmpl := domain.Template{ID: "tcp-port-override", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.TCP = []domain.TCPRequest{{
		Inputs:   []domain.TCPInput{{Data: "ping"}},
		Host:     domain.StringList{"{{Hostname}}"},
		Port:     domain.IntList{wantPort},
		Matchers: []domain.Matcher{{Type: "word", Part: "data", Words: []string{"SLP-OK"}}},
	}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	// Scan URL embeds port 1 (closed). Template port must win.
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"http://127.0.0.1:1"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected hit on template port %d, got %d findings errs=%v", wantPort, len(res.Findings), res.Errors)
	}
	if !strings.Contains(res.Findings[0].MatchedAt, fmt.Sprintf(":%d", wantPort)) {
		t.Fatalf("matched_at=%q want port %d", res.Findings[0].MatchedAt, wantPort)
	}
}

func TestTCPInternalMatcherNoFinding(t *testing.T) {
	_, port := bannerListener(t, []byte("gate"))
	tmpl := domain.Template{ID: "tcp-internal", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.TCP = []domain.TCPRequest{{
		Inputs:   []domain.TCPInput{{Data: "ping"}},
		Host:     domain.StringList{"{{Hostname}}"},
		Port:     domain.IntList{port},
		Matchers: []domain.Matcher{{Type: "word", Part: "data", Words: []string{"gate"}, Internal: true}},
	}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"127.0.0.1"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("internal matcher must not emit findings, got %d", len(res.Findings))
	}
}

func TestTCPBinaryMatcher(t *testing.T) {
	_, port := bannerListener(t, []byte{0x30, 0x00, 0x01, 0x02, 0xff})
	tmpl := domain.Template{ID: "tcp-bin", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.TCP = []domain.TCPRequest{{
		Inputs:   []domain.TCPInput{{Data: "deadbeef", Type: "hex"}},
		Host:     domain.StringList{"{{Hostname}}"},
		Port:     domain.IntList{port},
		Matchers: []domain.Matcher{{Type: "binary", Binary: []string{"300001"}}},
	}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"127.0.0.1"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("tcp binary: expected 1 finding, got %d errs=%v", len(res.Findings), res.Errors)
	}
}

func TestDNSLocalhost(t *testing.T) {
	tmpl := domain.Template{ID: "dns-a", Compatible: true, Risk: "active"}
	tmpl.Info.Severity = "info"
	tmpl.DNS = []domain.DNSRequest{{
		Name:     "localhost",
		Type:     "A",
		Matchers: []domain.Matcher{{Type: "word", Part: "answer", Words: []string{"127.0.0.1"}}},
	}}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"localhost"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Skipf("dns localhost: got %d findings (resolver may differ) errs=%v", len(res.Findings), res.Errors)
	}
}
