package engine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"wscan/internal/domain"
	"wscan/internal/engine/js"
	tpl "wscan/internal/template"
)

func TestJSNetEcho(t *testing.T) {
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
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write([]byte("ECHO:" + string(buf[:n])))
				}
			}(c)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	code := `
		const c = require("nuclei/net");
		let conn = c.Open("tcp", Host + ":" + Port);
		conn.Send("ping");
		let resp = conn.RecvString(64);
		conn.Close();
		Export(resp);
	`
	res := js.Run(context.Background(), code, `isPortOpen(Host, Port)`, map[string]any{
		"Host": "127.0.0.1",
		"Port": port,
	}, nil, "", 5*time.Second)
	if !res.Success {
		t.Fatalf("expected success, err=%q response=%v", res.Error, res.Response)
	}
	if !strings.Contains(jsResponseString(res.Response), "ECHO:ping") {
		t.Fatalf("response=%v", res.Response)
	}
}

func TestJSPreconditionSkip(t *testing.T) {
	res := js.Run(context.Background(), `Export("should-not-run")`, `isPortOpen("127.0.0.1", 1)`, map[string]any{}, nil, "", time.Second)
	if res.Success {
		t.Fatal("expected precondition to skip")
	}
	if jsResponseString(res.Response) != "" && strings.Contains(jsResponseString(res.Response), "should-not-run") {
		t.Fatalf("main script ran: %v", res.Response)
	}
}

func TestParseJavaScriptCompatible(t *testing.T) {
	raw := []byte(`
id: js-net-probe
info:
  name: JS Net Probe
  severity: info
javascript:
  - pre-condition: |
      isPortOpen(Host,Port);
    code: |
      const c = require("nuclei/net");
      let conn = c.Open("tcp", Host + ":" + Port);
      conn.Send("x");
      Export(conn.RecvString(8));
    args:
      Host: "{{Host}}"
      Port: "{{Port}}"
    matchers:
      - type: word
        words:
          - "x"
`)
	tm, err := tpl.ForExecution(raw, "javascript/test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !tm.Compatible {
		t.Fatalf("expected compatible, unsupported=%v", tm.Unsupported)
	}
	if len(tm.JavaScript) != 1 {
		t.Fatalf("javascript blocks: %d", len(tm.JavaScript))
	}
}

func TestExecJavaScriptFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Use a plain TCP echo via net for finding path (not HTTP server).
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
				buf := make([]byte, 32)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write(buf[:n])
				}
			}(c)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	tmpl := domain.Template{
		ID: "js-echo", Compatible: true, Risk: "active",
		Info: struct {
			Name        string            `yaml:"name"`
			Severity    string            `yaml:"severity"`
			Tags        string            `yaml:"tags"`
			Description string            `yaml:"description"`
			Reference   domain.StringList `yaml:"reference"`
		}{Name: "echo", Severity: "info"},
		JavaScript: []domain.JavaScriptRequest{{
			Code: `
				const c = require("nuclei/net");
				let conn = c.Open("tcp", Host + ":" + Port);
				conn.Send("hello");
				let r = conn.RecvString(32);
				conn.Close();
				r;
			`,
			Args: map[string]any{"Host": "127.0.0.1", "Port": portStr},
			Matchers: []domain.Matcher{{
				Type:  "word",
				Words: []string{"hello"},
			}},
		}},
	}
	e := New(nil, Config{TimeoutSeconds: 5})
	fs, errs := e.execTemplate(context.Background(), tmpl, "127.0.0.1:"+portStr, execContext{timeout: 5})
	if len(errs) > 0 {
		t.Fatalf("errs=%v", errs)
	}
	if len(fs) != 1 {
		t.Fatalf("findings=%v", fs)
	}
}

// TestClusterbombCredentialEvidenceShowsWinningCombo reproduces a real
// user-confusion report: javascript/default-logins/smb-default-login.yaml
// (and 22 other library templates using the same args: User/Pass
// convention — ldap-default-login.yaml, mysql-default-login.yaml, …) runs
// an attack: clusterbomb over a username/password payload list with
// stop-at-first-match, but without an extractor the finding's evidence only
// ever showed the script's own response (e.g. a share list) — never which
// credential pair actually won. For a "default login" finding that's the
// entire point, so execJavaScript now folds args["User"]/args["Pass"] (the
// already-rendered combo for the matching iteration) into the evidence.
func TestClusterbombCredentialEvidenceShowsWinningCombo(t *testing.T) {
	raw := []byte(`
id: fake-default-login
info:
  name: Fake Default Login
  severity: high
javascript:
  - code: |
      Export(User === "admin" && Pass === "admin");
    args:
      Host: "{{Host}}"
      User: "{{usernames}}"
      Pass: "{{passwords}}"
    attack: clusterbomb
    payloads:
      usernames:
        - wrongfirst
        - admin
      passwords:
        - wrongfirst
        - admin
    stop-at-first-match: true
    matchers:
      - type: dsl
        dsl:
          - "response == true"
`)
	tm, err := tpl.ForExecution(raw, "javascript/default-logins/fake-default-login.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !tm.Compatible {
		t.Fatalf("expected compatible, unsupported=%v", tm.Unsupported)
	}
	e := New(nil, Config{TimeoutSeconds: 5})
	fs, errs := e.execTemplate(context.Background(), tm, "127.0.0.1", execContext{timeout: 5})
	if len(errs) > 0 {
		t.Fatalf("errs=%v", errs)
	}
	if len(fs) != 1 {
		t.Fatalf("findings=%v", fs)
	}
	if !strings.Contains(fs[0].Evidence, `user="admin"`) || !strings.Contains(fs[0].Evidence, `pass="admin"`) {
		t.Fatalf("evidence missing winning credential pair: %q", fs[0].Evidence)
	}
}

func TestBytesNewBuffer(t *testing.T) {
	code := `
		let packet = bytes.NewBuffer();
		packet.WriteString("hi");
		Export(packet.Hex());
	`
	res := js.Run(context.Background(), code, "", nil, nil, "", time.Second)
	if !res.Success {
		t.Fatalf("err=%q", res.Error)
	}
	if jsResponseString(res.Response) != "6869" {
		t.Fatalf("got %v", res.Response)
	}
}
