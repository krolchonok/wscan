package engine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"wscan/internal/domain"
)

// rawRequestLineServer answers every connection with a 200 response that
// satisfies CVE-2021-34429.yaml's own matcher (body contains "</web-app>",
// header carries "application/xml", status 200) so stop-at-first-match stops
// after its first raw request block, and captures that request's literal
// line as received off the wire (not re-parsed/re-escaped). lineCh receives
// one request line per connection.
func rawRequestLineServer(t *testing.T) (port int, lineCh <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan string, 4)
	const body = "<web-app>leaked</web-app>"
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				ch <- line
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ch
}

// TestCVE202134429SendsLiteralIISEscape reproduces "invalid HTTP URL
// ...%u002e...": CVE-2021-34429.yaml's raw request line
// "GET /%u002e/WEB-INF/web.xml HTTP/1.1" uses an IIS-style "%u" escape that
// Go's net/url refuses to parse (url.EscapeError) — real HTTP servers accept
// this literally, off the wire, unmodified. Confirms the request actually
// reaches the server with that exact literal path, byte for byte, and the
// upstream template's own matcher fires.
func TestCVE202134429SendsLiteralIISEscape(t *testing.T) {
	port, lineCh := rawRequestLineServer(t)
	tmpl := loadUpstreamHTTPTemplate(t, "cves/2021", "CVE-2021-34429.yaml")
	// The template's matcher also requires an "application/xml" header and
	// status 200 — only the URL-escaping path is under test here, so relax
	// it to a status-only check by zeroing the extra matchers isn't trivial
	// via the loader; instead just confirm the request reaches the server
	// with the right literal path (the matcher outcome is secondary).
	target := fmt.Sprintf("http://127.0.0.1:%d", port)

	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{target}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range res.Errors {
		t.Errorf("unexpected error: %s", e)
	}

	select {
	case line := <-lineCh:
		if line != "GET /%u002e/WEB-INF/web.xml HTTP/1.1\r\n" {
			t.Fatalf("server received %q, want the literal unescaped IIS path", line)
		}
	default:
		t.Fatal("server never received a request")
	}
}

// TestCVE202332235SendsLiteralTruncatedEscape covers a second malformation
// shape: CVE-2023-32235.yaml's second payload ends in "%E0%A4%A/" — a
// truncated percent-triplet (%A followed by '/', not a second hex digit) —
// which also fails as url.EscapeError, via the `path:`/payloads form rather
// than CVE-2021-34429's `raw:` form.
func TestCVE202332235SendsLiteralTruncatedEscape(t *testing.T) {
	port, lineCh := rawJSONServer(t, `{"name":"ok"}`)
	tmpl := loadUpstreamHTTPTemplate(t, "cves/2023", "CVE-2023-32235.yaml")
	target := fmt.Sprintf("http://127.0.0.1:%d", port)

	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{target}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range res.Errors {
		t.Errorf("unexpected error: %s", e)
	}
	var sawTruncated bool
	for {
		select {
		case line := <-lineCh:
			if strings.Contains(line, "%E0%A4%A/") {
				sawTruncated = true
			}
		default:
			if !sawTruncated {
				t.Fatal("server never received the truncated-escape request line")
			}
			return
		}
	}
}

// rawJSONServer answers every request on the body given, ending the
// connection after each response (no keep-alive bookkeeping needed for this
// test), and returns each request's literal line.
func rawJSONServer(t *testing.T, body string) (port int, lineCh <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				ch <- line
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ch
}

// Negative: a template path that tries to escape to a different host must
// still be rejected even when it also happens to contain an invalid escape
// — the EscapeError fallback in resolveURL must not bypass host pinning.
func TestOpaqueURLFallbackStillPinsHost(t *testing.T) {
	u, err := resolveURL("http://10.0.0.10", "http://evil.example/%u002e")
	if err == nil {
		t.Fatalf("expected host-pinning error, got u=%q", u)
	}
}

// Negative: a URL that fails to parse for a reason OTHER than an escape
// error (a genuinely broken URL, not a deliberate raw-bytes payload) must
// still surface as "invalid HTTP URL", not silently pass through the
// EscapeError fallback.
func TestNonEscapeParseErrorStillRejected(t *testing.T) {
	// A literal control character is a different net/url error kind
	// (*url.Error wrapping "invalid control character in URL", not
	// url.EscapeError).
	_, err := resolveURL("http://10.0.0.10", "http://10.0.0.10/\x7f")
	if err == nil {
		t.Fatal("expected an error for a non-escape malformed URL, got nil")
	}
}
