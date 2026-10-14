package engine

import (
	"context"
	"fmt"
	"net"
	"testing"

	"wscan/internal/domain"
)

// TestJSCommaPortListDoesNotCrash reproduces "Ошибка проверки: CVE-2018-8011:
// javascript: dial tcp: lookup tcp/80,443: unknown port" — the template's
// args declare `Port: 80,443` literally, which net.Dial can't resolve as a
// single address. The explicitly selected service takes precedence.
func TestJSCommaPortListDoesNotCrash(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.1\r\n\r\n"))
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	tmpl := loadUpstreamJSTemplate(t, "cves/2018", "CVE-2018-8011.yaml")
	for i := range tmpl.JavaScript {
		// Reproduce the exact bug shape: args.Port is a comma list (first
		// entry is our real, reachable fake server; the second is
		// deliberately bogus, standing in for "443" when nothing runs
		// there) — not a single resolved port.
		args := make(map[string]any, len(tmpl.JavaScript[i].Args)+1)
		for k, v := range tmpl.JavaScript[i].Args {
			args[k] = v
		}
		args["Port"] = fmt.Sprintf("%d,443", port)
		args["Host"] = "127.0.0.1"
		tmpl.JavaScript[i].Args = args
	}

	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	target := fmt.Sprintf("http://127.0.0.1:%d", port)
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{target}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range res.Errors {
		t.Errorf("unexpected error: %s", e)
	}
}
