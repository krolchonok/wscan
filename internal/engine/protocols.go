package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"wscan/internal/domain"
)

// runTCP executes one TCP/network request block against a target: it sends the
// inputs over a connection and matches the bytes read back. Templates reference
// the response via matcher part "data"/"raw"/"body".
func runTCP(ctx context.Context, t domain.Template, req domain.TCPRequest, target string, vars map[string]any, tvars map[string]string, timeout time.Duration) ([]domain.Finding, []error) {
	hosts := req.Host
	if len(hosts) == 0 {
		hosts = []string{"{{Hostname}}"}
	}
	// req.Port is normally one value; a template may list several
	// ("port: 6379,6380") to probe, tried like the host list above.
	ports := req.Port
	if len(ports) == 0 {
		ports = []int{0} // 0 means "use the port already in the target"
	}
	var findings []domain.Finding
	var errs []error
	for _, h := range hosts {
		raw := applyTargetVars(render(h, vars), tvars)
		for _, p := range ports {
			addr, err := tcpDialAddr(raw, p)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", t.ID, err))
				continue
			}
			dialAddr := addr
			if strings.HasPrefix(strings.ToLower(raw), "tls://") {
				dialAddr = "tls://" + addr
			}
			resp, parts, err := tcpExchange(ctx, dialAddr, req, vars, tvars, timeout)
			if err != nil {
				var opErr *net.OpError
				closedProbe := errors.As(err, &opErr) && (opErr.Op == "dial" || req.UDP) && isBenignTCPProbeError(err)
				if !closedProbe {
					errs = append(errs, fmt.Errorf("%s %s: %w", t.ID, addr, err))
				}
				continue
			}
			env := map[string]any{"data": resp, "body": resp, "raw": resp}
			for k, v := range parts {
				env[k] = v
			}
			for k, v := range vars {
				if _, ok := env[k]; !ok {
					env[k] = v
				}
			}
			extra := runExtractors(req.Extractors, env, vars, nil, []byte(resp))
			matched, evidence := matchOrExtract(req.Matchers, req.MatchersCondition, 0, nil, []byte(resp), env, extra)
			if !matched {
				continue
			}
			// Nuclei internal matchers gate later steps; they must not emit findings.
			if matchersOnlyInternal(req.Matchers) {
				continue
			}
			proto := "tcp"
			if req.UDP || strings.HasPrefix(strings.ToLower(raw), "udp://") {
				proto = "udp"
			}
			findings = append(findings, domain.Finding{
				TemplateID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity,
				Target: addr, MatchedAt: proto + "://" + addr, Evidence: evidence,
				Risk: t.Risk, Protocol: proto, Time: time.Now().UTC(),
			})
		}
	}
	return findings, errs
}

// tcpDialAddr builds host:port for a TCP template. When the template sets port,
// it always wins over a port already embedded in Hostname (e.g. scan URL :80
// must not override OpenSLP :427).
func tcpDialAddr(host string, port int) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("empty TCP host")
	}
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?"); i >= 0 {
		host = host[:i]
	}
	h, embedded, err := net.SplitHostPort(host)
	if err != nil {
		h = host
		if port <= 0 {
			return "", fmt.Errorf("no port for TCP host %q", host)
		}
		return net.JoinHostPort(h, strconv.Itoa(port)), nil
	}
	if port > 0 {
		return net.JoinHostPort(h, strconv.Itoa(port)), nil
	}
	return net.JoinHostPort(h, embedded), nil
}

func matchersOnlyInternal(ms []domain.Matcher) bool {
	if len(ms) == 0 {
		return false
	}
	for _, m := range ms {
		if !m.Internal {
			return false
		}
	}
	return true
}

// isBenignTCPProbeError reproduces "nfs-v3-exposed 10.0.0.10:2049: dial tcp
// 10.0.0.10:2049: connect: connection refused" and
// "perforce-remote-depot-unauth 10.0.0.10:1666: ...: connection refused"
// surfacing as check errors. nuclei's network (tcp:) protocol has no
// pre-condition mechanism the way javascript: does — dialing the
// template-defined port IS the probe — so every detection template for a
// service that isn't running on this host hits exactly this error on every
// scan, on every closed port. That's the normal "not present here" outcome
// for a port probe, not a defect in our engine: mirrors discovery/ports.go's
// own discoveryOverload, which treats the same error family as normal
// closed/filtered ports during port scanning. A genuinely different failure
// (bad host/DNS, a malformed address) still surfaces as before.
func isBenignTCPProbeError(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, p := range []string{
		"connection refused",
		"connection reset",
		"target machine actively refused", // Windows WSAECONNREFUSED
		"connection was forcibly closed",  // Windows WSAECONNRESET
		"no route to host",
		"i/o timeout",
		"deadline exceeded",
		"network is unreachable",
	} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

// tcpExchange dials addr (TCP or UDP when req.UDP / udp:// host), writes each
// input (hex-decoded when type is hex, or the rendered text otherwise) and
// returns up to read-size bytes read back.
func tcpExchange(ctx context.Context, addr string, req domain.TCPRequest, vars map[string]any, tvars map[string]string, timeout time.Duration) (string, map[string]string, error) {
	secure := strings.HasPrefix(strings.ToLower(addr), "tls://")
	if secure {
		addr = addr[len("tls://"):]
	}
	network := "tcp"
	if req.UDP {
		network = "udp"
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if secure {
		host, _, _ := net.SplitHostPort(addr)
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return "", nil, fmt.Errorf("TLS handshake: %w", err)
		}
		conn = tlsConn
	}
	parts := map[string]string{}
	var response strings.Builder
	read := func(size int, name string) error {
		buf := make([]byte, size)
		n, err := conn.Read(buf)
		if n == 0 && err != nil {
			return fmt.Errorf("read response: %w", err)
		}
		data := string(buf[:n])
		response.WriteString(data)
		if name != "" {
			parts[strings.ToLower(name)] = data
		}
		return nil
	}
	readDuringInputs := false
	for _, in := range req.Inputs {
		data := applyTargetVars(render(in.Data, vars), tvars)
		var payload []byte
		if strings.EqualFold(in.Type, "hex") {
			payload, err = hex.DecodeString(strings.TrimSpace(data))
			if err != nil {
				return "", nil, fmt.Errorf("invalid hex input: %w", err)
			}
		} else {
			payload = []byte(data)
		}
		if len(payload) > 0 {
			if _, err = conn.Write(payload); err != nil {
				return "", nil, err
			}
		}
		if in.Read > 0 {
			readDuringInputs = true
			if err := read(in.Read, in.Name); err != nil {
				return "", nil, err
			}
		}
	}
	if !readDuringInputs || req.ReadSize > 0 {
		readSize := req.ReadSize
		if readSize <= 0 {
			readSize = 4096
		}
		if err := read(readSize, ""); err != nil {
			return "", nil, err
		}
	}
	return response.String(), parts, nil
}

// runDNS executes one DNS request block: it resolves the name and matches a
// dig-like textual rendering of the answer (matcher part "answer"/"raw").
func runDNS(ctx context.Context, t domain.Template, req domain.DNSRequest, vars map[string]any, tvars map[string]string, timeout time.Duration) ([]domain.Finding, []error) {
	name := strings.TrimSuffix(applyTargetVars(render(req.Name, vars), tvars), ".")
	if name == "" {
		return nil, []error{fmt.Errorf("%s: empty DNS name", t.ID)}
	}
	qtype := strings.ToUpper(req.Type)
	if qtype == "" {
		qtype = "A"
	}
	answer, err := dnsQuery(ctx, name, qtype, timeout)
	if err != nil {
		return nil, []error{fmt.Errorf("%s %s %s: %w", t.ID, qtype, name, err)}
	}
	env := map[string]any{"answer": answer, "body": answer, "raw": answer, "question": name}
	for k, v := range vars {
		if _, ok := env[k]; !ok {
			env[k] = v
		}
	}
	extra := runExtractors(req.Extractors, env, vars, nil, []byte(answer))
	matched, evidence := matchOrExtract(req.Matchers, req.MatchersCondition, 0, nil, []byte(answer), env, extra)
	if !matched {
		return nil, nil
	}
	if matchersOnlyInternal(req.Matchers) {
		return nil, nil
	}
	return []domain.Finding{{
		TemplateID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity,
		Target: name, MatchedAt: "dns://" + name + "/" + qtype, Evidence: evidence,
		Risk: t.Risk, Protocol: "dns", Time: time.Now().UTC(),
	}}, nil
}

// runSSL connects over TLS and matches the leaf certificate's fields. The cert
// fields are exposed both as matcher parts (part: issuer_dn, subject_cn, ...) and
// as env values for json extractors. min_version/max_version constrain the
// handshake; tls_version and cipher are recorded from the negotiated suite.
func runSSL(ctx context.Context, t domain.Template, req domain.SSLRequest, target string, vars map[string]any, tvars map[string]string, timeout time.Duration) ([]domain.Finding, []error) {
	addr := applyTargetVars(render(req.Address, vars), tvars)
	if addr == "" {
		addr = net.JoinHostPort(tvars["Host"], tvars["Port"])
	}
	addr = rewriteSSLAddress(addr)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := tvars["Port"]
		if port == "" {
			port = "443"
		}
		addr = net.JoinHostPort(addr, port)
	}
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: tvars["Hostname"]}
	if v := tlsVersionNum(req.MinVersion); v != 0 {
		cfg.MinVersion = v
	}
	if v := tlsVersionNum(req.MaxVersion); v != 0 {
		cfg.MaxVersion = v
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(&d, "tcp", addr, cfg)
	if err != nil {
		return nil, []error{fmt.Errorf("%s %s: %w", t.ID, addr, err)}
	}
	defer conn.Close()
	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, []error{fmt.Errorf("%s %s: no peer certificate", t.ID, addr)}
	}
	env := certEnv(certs[0])
	env["tls_version"] = tlsVersionName(state.Version)
	env["cipher"] = tls.CipherSuiteName(state.CipherSuite)
	for k, v := range vars {
		if _, ok := env[k]; !ok {
			env[k] = v
		}
	}
	dump := env["raw"].(string)
	extra := runExtractors(req.Extractors, env, vars, nil, []byte(dump))
	matched, evidence := matchOrExtract(req.Matchers, req.MatchersCondition, 0, nil, []byte(dump), env, extra)
	if !matched {
		return nil, nil
	}
	if matchersOnlyInternal(req.Matchers) {
		return nil, nil
	}
	return []domain.Finding{{
		TemplateID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity,
		Target: addr, MatchedAt: "ssl://" + addr, Evidence: evidence,
		Risk: t.Risk, Protocol: "ssl", Time: time.Now().UTC(),
	}}, nil
}

func tlsVersionNum(s string) uint16 {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tls10", "tls1.0", "1.0":
		return tls.VersionTLS10
	case "tls11", "tls1.1", "1.1":
		return tls.VersionTLS11
	case "tls12", "tls1.2", "1.2":
		return tls.VersionTLS12
	case "tls13", "tls1.3", "1.3":
		return tls.VersionTLS13
	}
	return 0
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "tls10"
	case tls.VersionTLS11:
		return "tls11"
	case tls.VersionTLS12:
		return "tls12"
	case tls.VersionTLS13:
		return "tls13"
	}
	return fmt.Sprintf("0x%04x", v)
}

// certEnv maps a certificate's fields to the names ssl templates reference.
func certEnv(c *x509.Certificate) map[string]any {
	env := map[string]any{
		"subject_dn": c.Subject.String(),
		"issuer_dn":  c.Issuer.String(),
		"subject_cn": c.Subject.CommonName,
		"issuer_cn":  c.Issuer.CommonName,
		"serial":     c.SerialNumber.String(),
		"not_before": c.NotBefore.Format(time.RFC3339),
		"not_after":  c.NotAfter.Format(time.RFC3339),
		"expired":    fmt.Sprintf("%t", time.Now().After(c.NotAfter)),
		"wildcard":   fmt.Sprintf("%t", strings.HasPrefix(c.Subject.CommonName, "*.")),
	}
	sans := append(append([]string{}, c.DNSNames...), c.EmailAddresses...)
	env["subject_an"] = strings.Join(sans, ", ")
	env["dns_names"] = strings.Join(c.DNSNames, ", ")
	var dump strings.Builder
	for _, k := range []string{"subject_dn", "issuer_dn", "subject_cn", "issuer_cn", "serial", "not_before", "not_after", "subject_an"} {
		fmt.Fprintf(&dump, "%s: %s\n", k, env[k])
	}
	env["raw"] = dump.String()
	env["body"] = dump.String()
	return env
}

// dnsQuery resolves name for the given record type and renders the answer as
// dig-style tab-separated lines, which the template matchers/extractors expect.
func dnsQuery(ctx context.Context, name, qtype string, timeout time.Duration) (string, error) {
	r := &net.Resolver{}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lines []string
	switch qtype {
	case "A", "AAAA":
		ips, err := r.LookupIP(cctx, map[string]string{"A": "ip4", "AAAA": "ip6"}[qtype], name)
		if err != nil {
			return "", err
		}
		for _, ip := range ips {
			lines = append(lines, fmt.Sprintf("%s\tIN\t%s\t%s", name, qtype, ip.String()))
		}
	case "CNAME":
		cname, err := r.LookupCNAME(cctx, name)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("%s\tIN\tCNAME\t%s", name, cname))
	case "MX":
		mxs, err := r.LookupMX(cctx, name)
		if err != nil {
			return "", err
		}
		for _, mx := range mxs {
			lines = append(lines, fmt.Sprintf("%s\tIN\tMX\t%d %s", name, mx.Pref, mx.Host))
		}
	case "NS":
		nss, err := r.LookupNS(cctx, name)
		if err != nil {
			return "", err
		}
		for _, ns := range nss {
			lines = append(lines, fmt.Sprintf("%s\tIN\tNS\t%s", name, ns.Host))
		}
	case "TXT":
		txts, err := r.LookupTXT(cctx, name)
		if err != nil {
			return "", err
		}
		for _, txt := range txts {
			lines = append(lines, fmt.Sprintf("%s\tIN\tTXT\t%q", name, txt))
		}
	default:
		return "", fmt.Errorf("unsupported DNS type %s", qtype)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n"), nil
}
