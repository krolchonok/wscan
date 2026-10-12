package js

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// This is a wscan API, deliberately separate from the upstream nuclei/smtp API.
func mailAuditModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	o := vm.NewObject()
	_ = o.Set("Audit", func(host string, port int, protocol string, implicit bool, serverName string) (string, error) {
		return auditMail(ctx, host, port, protocol, implicit, serverName, timeout)
	})
	_ = o.Set("SPF", func(domain string) (string, error) { return auditSPF(ctx, domain) })
	return o
}

type mailWire struct {
	conn     net.Conn
	r        *bufio.Reader
	protocol string
}

// Each response is bounded by 16 KiB / 128 lines; tagged IMAP responses and
// SMTP continuation replies must complete before the next command is sent.
func (w *mailWire) response(tag string) (string, error) {
	var b strings.Builder
	smtpCode := ""
	for i := 0; i < 128; i++ {
		data, err := w.r.ReadSlice('\n')
		if err != nil {
			return "", err
		}
		line := string(data)
		if b.Len()+len(line) > 16384 {
			return "", fmt.Errorf("mail response exceeds 16 KiB")
		}
		b.WriteString(line)
		s := strings.TrimSpace(line)
		switch w.protocol {
		case "smtp":
			if len(s) < 3 {
				return "", fmt.Errorf("invalid SMTP reply")
			}
			if _, err := strconv.Atoi(s[:3]); err != nil {
				return "", fmt.Errorf("invalid SMTP reply")
			}
			if smtpCode != "" && smtpCode != s[:3] {
				return "", fmt.Errorf("inconsistent SMTP continuation code")
			}
			smtpCode = s[:3]
			if len(s) == 3 || s[3] == ' ' {
				return b.String(), nil
			}
			if s[3] != '-' {
				return "", fmt.Errorf("invalid SMTP continuation")
			}
		case "imap":
			if tag == "" || strings.HasPrefix(s, "+") || strings.HasPrefix(strings.ToUpper(s), strings.ToUpper(tag)+" ") {
				return b.String(), nil
			}
		case "pop3":
			if tag != "multiline" || s == "." || (i == 0 && strings.HasPrefix(s, "-ERR")) {
				return b.String(), nil
			}
		}
	}
	return "", fmt.Errorf("mail response exceeds 128 lines")
}

func (w *mailWire) command(cmd, tag string) (string, error) {
	if _, err := fmt.Fprintf(w.conn, "%s\r\n", cmd); err != nil {
		return "", err
	}
	return w.response(tag)
}

func mailOK(protocol, response, tag string) bool {
	s := strings.ToUpper(strings.TrimSpace(response))
	switch protocol {
	case "smtp":
		return strings.HasPrefix(s, "250 ") || strings.HasPrefix(s, "250-")
	case "pop3":
		return strings.HasPrefix(s, "+OK")
	case "imap":
		for _, line := range strings.Split(s, "\n") {
			s := strings.TrimSpace(line)
			if s == strings.ToUpper(tag)+" OK" || strings.HasPrefix(s, strings.ToUpper(tag)+" OK ") {
				return true
			}
		}
	}
	return false
}

func openMail(ctx context.Context, address, protocol string, implicit bool, cfg *tls.Config) (*mailWire, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	w := &mailWire{conn: raw, protocol: protocol}
	if implicit {
		t := tls.Client(raw, cfg)
		if err = t.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		w.conn = t
	}
	w.r = bufio.NewReaderSize(w.conn, 16384)
	greeting, err := w.response("")
	if err == nil {
		s := strings.ToUpper(greeting)
		valid := protocol == "smtp" && strings.HasPrefix(s, "220 ") || protocol == "smtp" && strings.HasPrefix(s, "220-") || protocol == "imap" && strings.HasPrefix(s, "* OK") || protocol == "pop3" && strings.HasPrefix(s, "+OK")
		if !valid {
			err = fmt.Errorf("unexpected %s greeting", protocol)
		}
	}
	if err != nil {
		w.conn.Close()
		return nil, err
	}
	return w, nil
}

func (w *mailWire) capabilities() (string, error) {
	var cmd, tag string
	switch w.protocol {
	case "smtp":
		cmd = "EHLO audit.invalid"
	case "imap":
		cmd = "a1 CAPABILITY"
		tag = "a1"
	case "pop3":
		cmd = "CAPA"
		tag = "multiline"
	}
	r, err := w.command(cmd, tag)
	if err != nil {
		return "", err
	}
	if !mailOK(w.protocol, r, tag) {
		return "", fmt.Errorf("%s capability command rejected", w.protocol)
	}
	return strings.ToUpper(r), nil
}

func (w *mailWire) upgrade(ctx context.Context, cfg *tls.Config) error {
	cmd, tag := "STARTTLS", ""
	if w.protocol == "imap" {
		cmd, tag = "a2 STARTTLS", "a2"
	}
	if w.protocol == "pop3" {
		cmd = "STLS"
	}
	r, err := w.command(cmd, tag)
	if err != nil {
		return err
	}
	ok := mailOK(w.protocol, r, tag)
	if w.protocol == "smtp" {
		ok = strings.HasPrefix(r, "220 ") || strings.HasPrefix(r, "220\r")
	}
	if !ok {
		return fmt.Errorf("%s TLS upgrade rejected", w.protocol)
	}
	if w.r.Buffered() != 0 {
		return fmt.Errorf("unexpected bytes buffered before TLS")
	}
	t := tls.Client(w.conn, cfg)
	if err = t.HandshakeContext(ctx); err != nil {
		return err
	}
	w.conn = t
	w.r = bufio.NewReaderSize(t, 16384)
	return nil
}

// Probe a SASL continuation and immediately cancel it. No credentials are sent.
// A continuation proves credential exchange is allowed, not successful login.
func (w *mailWire) authProbe(caps string) ([]string, error) {
	var results []string
	mechanisms := []string{"PLAIN"}
	if w.protocol == "smtp" {
		mechanisms = append(mechanisms, "LOGIN")
	}
	for i, m := range mechanisms {
		advertised := false
		for _, line := range strings.Split(caps, "\n") {
			if w.protocol == "smtp" && len(line) > 4 {
				fields := strings.Fields(strings.ReplaceAll(line[4:], "=", " "))
				if len(fields) == 0 || fields[0] != "AUTH" {
					continue
				}
				for _, v := range fields[1:] {
					if v == m {
						advertised = true
					}
				}
			}
			if w.protocol == "imap" {
				for _, v := range strings.Fields(line) {
					if v == "AUTH="+m {
						advertised = true
					}
				}
			}
			if w.protocol == "pop3" && strings.HasPrefix(strings.TrimSpace(line), "SASL ") {
				for _, v := range strings.Fields(line) {
					if v == m {
						advertised = true
					}
				}
			}
		}
		if !advertised {
			continue
		}
		cmd, tag := "AUTH "+m, ""
		if w.protocol == "imap" {
			tag = fmt.Sprintf("p%d", i)
			cmd = tag + " AUTHENTICATE " + m
		}
		r, err := w.command(cmd, tag)
		if err != nil {
			return results, err
		}
		continuation := strings.HasPrefix(r, "334")
		if w.protocol != "smtp" {
			continuation = strings.HasPrefix(r, "+") && !strings.HasPrefix(r, "+OK")
		}
		status := "announced; credential exchange not accepted"
		if continuation {
			status = "credential exchange accepted before TLS; login not attempted"
			cancelReply, err := w.command("*", tag)
			if err != nil {
				return results, err
			}
			cancelled := false
			switch w.protocol {
			case "smtp":
				cancelled = strings.HasPrefix(cancelReply, "4") || strings.HasPrefix(cancelReply, "5")
			case "pop3":
				cancelled = strings.HasPrefix(cancelReply, "-ERR")
			case "imap":
				for _, line := range strings.Split(strings.ToUpper(cancelReply), "\n") {
					line = strings.TrimSpace(line)
					cancelled = cancelled || strings.HasPrefix(line, strings.ToUpper(tag)+" BAD ") || strings.HasPrefix(line, strings.ToUpper(tag)+" NO ") || line == strings.ToUpper(tag)+" BAD" || line == strings.ToUpper(tag)+" NO"
				}
			}
			if !cancelled {
				return results, fmt.Errorf("SASL cancellation not confirmed; closing connection")
			}
		}
		results = append(results, m+": "+status)
	}
	return results, nil
}

func auditMail(ctx context.Context, host string, port int, protocol string, implicit bool, serverName string, timeout time.Duration) (string, error) {
	if protocol != "smtp" && protocol != "imap" && protocol != "pop3" {
		return "", fmt.Errorf("unsupported mail protocol")
	}
	if port < 1 || port > 65535 || strings.ContainsAny(host+serverName, "\r\n\x00") {
		return "", fmt.Errorf("invalid mail target")
	}
	if serverName == "" {
		serverName = host
	}
	if timeout <= 0 || timeout > 15*time.Second {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	address := net.JoinHostPort(host, strconv.Itoa(port))
	// Collect invalid certificates too, then verify explicitly with system roots.
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	w, err := openMail(ctx, address, protocol, implicit, cfg)
	if err != nil {
		return "", err
	}
	defer func() { w.conn.Close() }()
	caps, err := w.capabilities()
	if err != nil {
		return "", err
	}
	lines := []string{fmt.Sprintf("MAIL_AUDIT protocol=%s target=%s implicit_tls=%t", protocol, address, implicit)}
	if !implicit {
		probes, err := w.authProbe(caps)
		for _, p := range probes {
			lines = append(lines, "AUTH: "+p)
		}
		if err != nil {
			return "", fmt.Errorf("AUTH probe: %w", err)
		}
		if protocol == "imap" {
			lines = append(lines, fmt.Sprintf("IMAP LOGINDISABLED announced=%t; LOGIN not attempted", strings.Contains(caps, "LOGINDISABLED")))
		}
		if protocol == "pop3" {
			lines = append(lines, "POP3 USER/PASS not attempted; SASL PLAIN checked only if announced")
		}
		upgradeToken := "STARTTLS"
		if protocol == "pop3" {
			upgradeToken = "STLS"
		}
		announced := false
		for _, token := range strings.Fields(caps) {
			if token == upgradeToken || token == "250-"+upgradeToken {
				announced = true
			}
		}
		lines = append(lines, fmt.Sprintf("%s announced=%t", upgradeToken, announced))
		if !announced {
			return strings.Join(lines, "\n"), nil
		}
		if err = w.upgrade(ctx, cfg); err != nil {
			return "", fmt.Errorf("TLS upgrade: %w", err)
		}
	}
	state := w.conn.(*tls.Conn).ConnectionState()
	lines = append(lines, "TLS handshake=success version="+tls.VersionName(state.Version)+" cipher="+tls.CipherSuiteName(state.CipherSuite))
	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == state.CipherSuite {
			lines = append(lines, "negotiated cipher is classified insecure by Go TLS")
			break
		}
	}
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("TLS peer supplied no certificate")
	}
	leaf := state.PeerCertificates[0]
	lines = append(lines, "certificate not_before="+leaf.NotBefore.UTC().Format(time.RFC3339)+" not_after="+leaf.NotAfter.UTC().Format(time.RFC3339))
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Intermediates: intermediates})
	if verifyErr != nil {
		lines = append(lines, "certificate verification=failed: "+verifyErr.Error())
	} else {
		lines = append(lines, "certificate verification=valid for "+serverName+" with system roots")
	}
	// Two additional connections, always to the same selected service. Failures
	// are inconclusive (network/policy/runtime), never proof a version is disabled.
	w.conn.Close()
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		probeCfg := cfg.Clone()
		probeCfg.MinVersion = v
		probeCfg.MaxVersion = v
		probeCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		p, e := openMail(probeCtx, address, protocol, implicit, probeCfg)
		if e == nil && !implicit {
			_, e = p.capabilities()
			if e == nil {
				e = p.upgrade(probeCtx, probeCfg)
			}
		}
		if p != nil {
			p.conn.Close()
		}
		stop()
		if e == nil {
			lines = append(lines, "legacy TLS supported="+tls.VersionName(v))
		} else {
			lines = append(lines, "legacy TLS probe="+tls.VersionName(v)+" inconclusive: "+e.Error())
		}
	}
	return strings.Join(lines, "\n"), nil
}
