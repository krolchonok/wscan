package discovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"wscan/internal/domain"
	"wscan/internal/engine/js"
)

var (
	productVersionRE = regexp.MustCompile(`(?i)([a-z][a-z0-9_.+-]{1,39})[/ ]([0-9][a-z0-9._+-]{0,39})`)
	sshVersionRE     = regexp.MustCompile(`(?i)^SSH-[0-9.]+-([^_ \t]+)_([^ \t\r\n]+)`)
)

// identifyService performs bounded, low-impact protocol identification on an
// already-open TCP connection. It uses server banners, HTTP HEAD, and Redis
// PING; it never authenticates or sends application data that changes state.
func identifyService(ctx context.Context, conn net.Conn, service domain.Service, timeout time.Duration) domain.Service {
	if timeout <= 0 || timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	// Kyocera Net Viewer commonly uses HTTPS on 9091, while other software
	// uses plain HTTP there. Identify the actual transport before routing Web
	// checks; the port number alone must not declare a Kyocera service.
	if service.Port == 9091 && service.Name == "" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: service.Host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
		if err := tlsConn.HandshakeContext(ctx); err == nil {
			candidate := service
			candidate.Tunnel = "ssl"
			return identifyHTTP(tlsConn, candidate, deadline)
		}
		// A failed TLS handshake consumes the original stream. Reconnect for
		// a bounded, read-only HEAD probe of a possible plain HTTP service.
		dialer := net.Dialer{Timeout: timeout}
		plain, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(service.Host, fmt.Sprint(service.Port)))
		if err != nil {
			return service
		}
		defer plain.Close()
		plainDeadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(plainDeadline) {
			plainDeadline = d
		}
		return identifyHTTP(plain, service, plainDeadline)
	}

	if service.Tunnel == "ssl" {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         service.Host,
			InsecureSkipVerify: true, // Service identification does not trust the peer certificate.
			MinVersion:         tls.VersionTLS10,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return service
		}
		conn = tlsConn
	}

	if isHTTPService(service) {
		service = identifyHTTP(conn, service, deadline)
		return service
	}
	if service.Port == 6379 {
		return identifyRedis(conn, service, deadline)
	}
	if service.Port == 1433 || strings.Contains(strings.ToLower(service.Name), "ms-sql") || strings.EqualFold(service.Name, "mssql") {
		if identified, ok := identifyMSSQL(ctx, service, timeout); ok {
			return identified
		}
	}
	if banner := readBanner(conn); banner != "" {
		return identifyBanner(service, banner)
	}
	// SMB never speaks first, so readBanner above always times out against
	// it — this is the active probe nmap's -sV equivalent runs to recognize
	// SMB (and read its Windows build) on any port, not just 445. It only
	// runs once the passive wait has already come up empty, so it costs
	// nothing extra for every other silent-but-identified-by-port-number
	// service. Deadline is deliberately NOT inherited from the exhausted
	// `deadline` above (readBanner already consumed that whole budget) — it
	// gets its own short, ctx-bounded window instead.
	if service.Port != 1433 {
		if identified, ok := identifyMSSQL(ctx, service, smbProbeTimeout(ctx)); ok {
			return identified
		}
	}
	if probed, ok := identifySMB(conn, service, smbProbeTimeout(ctx)); ok {
		return probed
	}
	return service
}

// smbProbeTimeout bounds identifySMB's probe to at most 900ms, further
// capped by whatever remains of the ambient context deadline — the same
// starvation mistake found with resolveNetBIOSName (an unbounded wait against
// a silent target eating a shared time budget) must not repeat here.
func smbProbeTimeout(ctx context.Context) time.Duration {
	const budget = 900 * time.Millisecond
	if d, ok := ctx.Deadline(); ok {
		if remaining := time.Until(d); remaining < budget {
			if remaining <= 0 {
				return 0
			}
			return remaining
		}
	}
	return budget
}

func readBanner(conn net.Conn) string {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if n == 0 || err != nil && err != io.EOF {
		return ""
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(buffer[:n]), ""))
}

func identifyBanner(service domain.Service, banner string) domain.Service {
	// Banners may be followed by binary protocol bytes (e.g. SSH KEX); only
	// the first line is meaningful for identification.
	line := banner
	if i := strings.IndexAny(banner, "\r\n"); i >= 0 {
		line = banner[:i]
	}
	lower := strings.ToLower(line)
	switch {
	case strings.HasPrefix(lower, "ssh-"):
		service.Name = "ssh"
		if match := sshVersionRE.FindStringSubmatch(line); len(match) == 3 {
			service.Product, service.Version = match[1], match[2]
		} else if parts := strings.SplitN(line, "-", 3); len(parts) == 3 {
			// SSH-2.0-dropbear or SSH-2.0-dropbear_2019.78
			rest := parts[2]
			if i := strings.IndexByte(rest, '_'); i > 0 {
				service.Product, service.Version = rest[:i], rest[i+1:]
			} else {
				service.Product = rest
			}
		}
		return service
	case strings.HasPrefix(lower, "220") && service.Port == 21:
		service.Name = "ftp"
	case strings.HasPrefix(lower, "220") && (service.Port == 25 || service.Port == 465 || service.Port == 587):
		service.Name = "smtp"
	case strings.HasPrefix(lower, "+ok") && (service.Port == 110 || service.Port == 995):
		service.Name = "pop3"
	case strings.HasPrefix(lower, "* ok") && (service.Port == 143 || service.Port == 993):
		service.Name = "imap"
	case strings.HasPrefix(lower, "mysql") || service.Port == 3306 && strings.Contains(banner, "\x00"):
		service.Name = "mysql"
	}
	if service.Product == "" {
		if match := productVersionRE.FindStringSubmatch(line); len(match) == 3 {
			service.Product, service.Version = match[1], match[2]
		}
	}
	return service
}

func isHTTPService(service domain.Service) bool {
	name := strings.ToLower(service.Name)
	// RPC over HTTP carries RPC PDUs; ordinary Web checks do not apply.
	if name == "ncacn_http" || name == "rpc-http" {
		return false
	}
	return strings.Contains(name, "http") || service.Port == 80 || service.Port == 443 || service.Port == 8000 || service.Port == 8008 || service.Port == 8080 || service.Port == 8081 || service.Port == 8443
}

func identifyHTTP(conn net.Conn, service domain.Service, deadline time.Time) domain.Service {
	_ = conn.SetDeadline(deadline)
	if _, err := fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: wscan-service-detection\r\nConnection: close\r\n\r\n", service.Host); err != nil {
		return service
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodHead})
	if err != nil {
		return service
	}
	_ = response.Body.Close()
	if response.StatusCode > 0 {
		if service.Tunnel == "ssl" {
			service.Name = "https"
		} else {
			service.Name = "http"
		}
	}
	if server := strings.TrimSpace(response.Header.Get("Server")); server != "" {
		service.Product = server
		if match := productVersionRE.FindStringSubmatch(server); len(match) == 3 {
			service.Product, service.Version = match[1], match[2]
		}
	}
	return service
}

func identifyRedis(conn net.Conn, service domain.Service, deadline time.Time) domain.Service {
	_ = conn.SetDeadline(deadline)
	if _, err := io.WriteString(conn, "PING\r\n"); err != nil {
		return service
	}
	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if n > 0 && err == nil {
		service.Name = "redis"
	}
	return service
}

func identifyMSSQL(ctx context.Context, service domain.Service, timeout time.Duration) (domain.Service, bool) {
	if timeout <= 0 {
		return service, false
	}
	metadata, err := js.NewMSSQLClient(ctx, timeout).CollectMetadata(service.Host, service.Port)
	if err != nil {
		return service, false
	}
	service.Name = "mssql"
	service.Product = "Microsoft SQL Server"
	service.Version, _ = metadata["Version"].(string)
	return service, true
}
