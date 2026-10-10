// Package oast is a self-hosted out-of-band application security testing (OAST)
// collaborator. It replaces the external interactsh service with our own
// listener: a template embeds a per-request callback URL, and an HTTP callback
// to that URL's token confirms that the injected payload executed on the target.
//
// Scope: HTTP(S) callbacks only. DNS-based OOB (a bare hostname lookup with no
// HTTP request) is not observed, because that needs an authoritative DNS server
// and a delegated domain, which this self-contained collaborator does not run.
package oast

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Placeholder is the template token substituted with a per-request callback URL.
const Placeholder = "{{interactsh-url}}"

// Interaction is one callback the collaborator observed for a token.
type Interaction struct {
	Protocol   string
	Request    string
	RemoteAddr string
	Time       time.Time
}

// Collaborator is the running OAST listener.
type Collaborator struct {
	port int
	host string
	srv  *http.Server
	mu   sync.Mutex
	hits map[string][]Interaction
}

// Start binds an HTTP listener on an ephemeral port and begins serving. host is
// the address targets use to reach this listener (it must be reachable from the
// target); when empty, Start detects the scanner's outbound IP.
func Start(host string) (*Collaborator, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = outboundIP()
	}
	if host == "" {
		ln.Close()
		return nil, fmt.Errorf("could not determine a reachable OAST host")
	}
	c := &Collaborator{
		port: ln.Addr().(*net.TCPAddr).Port,
		host: host,
		hits: map[string][]Interaction{},
	}
	c.srv = &http.Server{Handler: http.HandlerFunc(c.handle), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = c.srv.Serve(ln) }()
	return c, nil
}

func (c *Collaborator) handle(w http.ResponseWriter, r *http.Request) {
	if token := firstSegment(r.URL.Path); token != "" {
		var sb strings.Builder
		fmt.Fprintf(&sb, "%s %s %s\n", r.Method, r.URL.RequestURI(), r.Proto)
		fmt.Fprintf(&sb, "Host: %s\n", r.Host)
		_ = r.Header.Write(&sb)
		c.mu.Lock()
		c.hits[token] = append(c.hits[token], Interaction{Protocol: "http", Request: sb.String(), RemoteAddr: r.RemoteAddr, Time: time.Now()})
		c.mu.Unlock()
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

// NewURL returns a fresh token and the callback URL to embed for it. The URL has
// no scheme, matching nuclei's {{interactsh-url}}: a payload that prepends
// http:// reaches this listener, and the token is the URL's first path segment.
func (c *Collaborator) NewURL() (token, url string) {
	b := make([]byte, 13)
	_, _ = rand.Read(b)
	token = hex.EncodeToString(b)
	return token, fmt.Sprintf("%s:%d/%s", c.host, c.port, token)
}

// Poll waits up to timeout for at least one interaction on token.
func (c *Collaborator) Poll(ctx context.Context, token string, timeout time.Duration) []Interaction {
	deadline := time.Now().Add(timeout)
	for {
		c.mu.Lock()
		hits := append([]Interaction(nil), c.hits[token]...)
		c.mu.Unlock()
		if len(hits) > 0 {
			return hits
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// Addr is the host:port the collaborator advertises (for diagnostics).
func (c *Collaborator) Addr() string { return fmt.Sprintf("%s:%d", c.host, c.port) }

// Close stops the listener.
func (c *Collaborator) Close() error {
	if c.srv != nil {
		return c.srv.Close()
	}
	return nil
}

func firstSegment(path string) string {
	path = strings.TrimLeft(path, "/")
	if i := strings.IndexByte(path, '/'); i >= 0 {
		path = path[:i]
	}
	return path
}

// outboundIP reports the scanner's source IP for outbound traffic. The UDP
// "dial" sends no packets; it only selects the routing source address.
func outboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return firstNonLoopbackIP()
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && !addr.IP.IsLoopback() {
		return addr.IP.String()
	}
	return firstNonLoopbackIP()
}

func firstNonLoopbackIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}
