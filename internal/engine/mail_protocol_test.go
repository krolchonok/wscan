package engine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"wscan/internal/domain"
)

func TestSMTPCommandsTemplateReadsNamedResponses(t *testing.T) {
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
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = fmt.Fprint(c, "220 localhost ESMTP\r\n")
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					switch strings.Fields(scanner.Text())[0] {
					case "EHLO":
						_, _ = fmt.Fprint(c, "250-localhost\r\n250 STARTTLS\r\n")
					case "HELP":
						_, _ = fmt.Fprint(c, "214 This server supports EHLO HELP QUIT\r\n")
					case "QUIT":
						_, _ = fmt.Fprint(c, "221 Bye\r\n")
						return
					}
				}
			}()
		}
	}()
	tmpl := loadUpstreamNetworkTemplate(t, "enumeration/smtp", "smtp-commands-enum.yaml")
	port := ln.Addr().(*net.TCPAddr).Port
	for i := range tmpl.TCP {
		tmpl.TCP[i].Port = []int{port}
	}
	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 1, TimeoutSeconds: 1})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"127.0.0.1"}}, []domain.Template{tmpl})
	if err != nil || len(res.Errors) != 0 || len(res.Findings) != 2 {
		t.Fatalf("findings=%v errors=%v error=%v", res.Findings, res.Errors, err)
	}
	if !strings.Contains(res.Findings[0].Evidence, "STARTTLS") || strings.Contains(res.Findings[0].Evidence, "This server supports") {
		t.Fatalf("wrong EHLO evidence: %q", res.Findings[0].Evidence)
	}
	if !strings.Contains(res.Findings[1].Evidence, "This server supports") || strings.Contains(res.Findings[1].Evidence, "STARTTLS") {
		t.Fatalf("wrong HELP evidence: %q", res.Findings[1].Evidence)
	}
}

func TestTCPReadTimeoutIsReported(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		<-done
	}()
	tmpl := domain.Template{ID: "silent"}
	addr := ln.Addr().String()
	req := domain.TCPRequest{Host: []string{addr}, Matchers: []domain.Matcher{{Type: "word", Words: []string{"SMTP"}}}}
	findings, errs := runTCP(context.Background(), tmpl, req, addr, nil, nil, 50*time.Millisecond)
	if len(findings) != 0 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "read response") {
		t.Fatalf("findings=%v errors=%v", findings, errs)
	}
}
