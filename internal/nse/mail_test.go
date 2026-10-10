package nse

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
)

func mailServer(t *testing.T, mode string) int {
	t.Helper()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	config := certServer.TLS.Clone()
	certServer.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if mode == "tls" {
		ln = tls.NewListener(ln, config)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = fmt.Fprint(conn, "220 localhost ESMTP ready\r\n")
				scanner := bufio.NewScanner(conn)
				for scanner.Scan() {
					cmd := strings.ToUpper(scanner.Text())
					switch {
					case strings.HasPrefix(cmd, "EHLO"):
						_, _ = fmt.Fprint(conn, "250-localhost\r\n250-STARTTLS\r\n250 HELP\r\n")
					case cmd == "HELP":
						_, _ = fmt.Fprint(conn, "214 EHLO STARTTLS HELP QUIT\r\n")
					case cmd == "STARTTLS":
						_, _ = fmt.Fprint(conn, "220 Ready to start TLS\r\n")
						secure := tls.Server(conn, config)
						if secure.Handshake() != nil {
							return
						}
						conn = secure
						scanner = bufio.NewScanner(conn)
					case cmd == "QUIT":
						return
					default:
						_, _ = fmt.Fprint(conn, "500 Unsupported command\r\n")
					}
				}
			}()
		}
	}()
	return port
}

func TestSMTPCommandsPlainAndTLS(t *testing.T) {
	for _, mode := range []string{"plain", "tls"} {
		t.Run(mode, func(t *testing.T) {
			port := mailServer(t, mode)
			info := PortInfo{Number: port, Protocol: "tcp", State: "open", Service: "smtp"}
			if mode == "tls" {
				info.Service = "smtps"
				info.Tunnel = "ssl"
			}
			lib := libraryDir(t)
			res, ran, err := New(lib, Config{Timeout: time.Second}).Run(context.Background(), filepath.Join(lib, "nmap/scripts/smtp-commands.nse"), HostInfo{IP: "127.0.0.1", Name: "localhost"}, []PortInfo{info})
			if err != nil || !ran || len(res) != 1 {
				t.Fatalf("results=%v ran=%v error=%v", res, ran, err)
			}
			if !strings.Contains(res[0].Output, "STARTTLS") || !strings.Contains(res[0].Output, "EHLO STARTTLS HELP QUIT") {
				t.Fatalf("missing commands: %q", res[0].Output)
			}
		})
	}
}

func TestSMTPStartTLS(t *testing.T) {
	port := mailServer(t, "plain")
	path := filepath.Join(t.TempDir(), "starttls.nse")
	source := `local smtp = require "smtp"
portrule = function() return true end
action = function(host, port)
  local socket, err = smtp.connect(host, port, {recv_before=true, timeout=1000})
  assert(socket, err)
  local ok, response = smtp.starttls(socket)
  assert(ok, response)
  ok, response = smtp.ehlo(socket, "localhost")
  assert(ok, response)
  smtp.quit(socket)
  return response
end`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	res, ran, err := New(libraryDir(t), Config{Timeout: time.Second}).Run(context.Background(), path, HostInfo{IP: "127.0.0.1"}, []PortInfo{{Number: port, Protocol: "tcp", Service: "smtp"}})
	if err != nil || !ran || len(res) != 1 || !strings.Contains(res[0].Output, "STARTTLS") {
		t.Fatalf("results=%v ran=%v error=%v", res, ran, err)
	}
}

func TestRunnerReportsRuleAndActionErrors(t *testing.T) {
	for _, rule := range []string{"portrule", "hostrule"} {
		for _, phase := range []string{"rule", "action"} {
			t.Run(rule+"/"+phase, func(t *testing.T) {
				body := rule + ` = function() return true end
action = function() error("broken action") end`
				if phase == "rule" {
					body = rule + ` = function() error("broken rule") end
action = function() return "unexpected" end`
				}
				path := filepath.Join(t.TempDir(), "broken.nse")
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				res, _, err := New(libraryDir(t), Config{}).Run(context.Background(), path, HostInfo{IP: "127.0.0.1"}, []PortInfo{{Number: 25, Protocol: "tcp", Service: "smtp"}})
				if err == nil || !strings.Contains(err.Error(), "broken "+phase) || len(res) != 0 {
					t.Fatalf("results=%v error=%v", res, err)
				}
			})
		}
	}
}

func TestRunnerPreservesResultsAlongsideActionErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.nse")
	source := `portrule = function() return true end
action = function(host, port)
  if port.number == 25 then error("broken SMTP") end
  return "working service"
end`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	res, ran, err := New(libraryDir(t), Config{}).Run(context.Background(), path, HostInfo{IP: "127.0.0.1"}, []PortInfo{{Number: 25}, {Number: 587}})
	if !ran || err == nil || len(res) != 1 || res[0].Port != 587 {
		t.Fatalf("results=%v ran=%v error=%v", res, ran, err)
	}
}

func TestSocketReceiveLinesWaitsForFragmentedResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = server.Write([]byte("250-first"))
		_, _ = server.Write([]byte(" line\r\n250 second"))
		_, _ = server.Write([]byte(" line\r\n"))
	}()
	L := lua.NewState()
	defer L.Close()
	registerSocketType(L)
	ctrl := newControl(context.Background(), Config{Timeout: time.Second})
	defer ctrl.close()
	ud := L.NewUserData()
	ud.Value = &luaSocket{ctrl: ctrl, conn: client}
	L.SetMetatable(ud, L.GetTypeMetatable(socketType))
	L.SetGlobal("socket", ud)
	if err := L.DoString(`local ok, data = socket:receive_lines(2)
assert(ok, data)
assert(data == "250-first line\r\n250 second line\r\n", data)`); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerDoesNotCountUnmatchedRuleAsExecuted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "skip.nse")
	if err := os.WriteFile(path, []byte(`portrule = function() return false end
action = function() error("must not run") end`), 0600); err != nil {
		t.Fatal(err)
	}
	results, ran, err := New(libraryDir(t), Config{}).Run(context.Background(), path, HostInfo{IP: "127.0.0.1"}, []PortInfo{{Number: 25}})
	if ran || err != nil || len(results) != 0 {
		t.Fatalf("results=%v ran=%v error=%v", results, ran, err)
	}
}

func TestSMTPCommandsReportsClosedGreetingWithCause(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	lib := libraryDir(t)
	results, ran, err := New(lib, Config{Timeout: time.Second}).Run(context.Background(), filepath.Join(lib, "nmap/scripts/smtp-commands.nse"), HostInfo{IP: "127.0.0.1"}, []PortInfo{{Number: ln.Addr().(*net.TCPAddr).Port, Protocol: "tcp", Service: "smtp"}})
	if err != nil || !ran || len(results) != 1 {
		t.Fatalf("results=%v ran=%v error=%v", results, ran, err)
	}
	output := results[0].Output
	if !OutputIsError(output) || !strings.Contains(output, "tcp 127.0.0.1:") || !strings.Contains(output, "EOF") {
		t.Fatalf("missing transport cause or error classification: %q", output)
	}
}
