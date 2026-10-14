package adscan

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Include machine-readable details while preserving errors.Is/errors.As.
func accessFailure(stage string, started time.Time, err error) error {
	if err == nil {
		return nil
	}
	fields := []string{stage, fmt.Sprintf("elapsed=%s error_type=%T", time.Since(started).Round(time.Millisecond), err)}
	var networkError net.Error
	if errors.As(err, &networkError) {
		fields = append(fields, fmt.Sprintf("timeout=%t", networkError.Timeout()))
	}
	var operation *net.OpError
	if errors.As(err, &operation) {
		fields = append(fields, "network="+operation.Net+" op="+operation.Op)
		if operation.Source != nil {
			fields = append(fields, "local="+operation.Source.String())
		}
		if operation.Addr != nil {
			fields = append(fields, "remote="+operation.Addr.String())
		}
	}
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		fields = append(fields, fmt.Sprintf("ldap_code=%d", ldapError.ResultCode))
	}
	return fmt.Errorf("%s: %w", strings.Join(fields, " · "), err)
}

// AccessDiagnostics intentionally excludes secrets, ticket contents and hashes.
func AccessDiagnostics(o AccessOptions) []string {
	auth := "anonymous"
	if o.Credential.Username != "" {
		auth = "selected credential (" + o.Credential.Type + ")"
	}
	if o.NoPreauthUser != "" {
		auth = "known user without pre-auth"
	}
	if o.TGTFile != "" {
		auth = "TGT file"
	}
	lines := []string{fmt.Sprintf("AD mode=%s host=%s domain=%s auth=%s", o.Mode, o.Host, o.Domain, auth)}
	port := o.LDAPPort
	if port == 0 {
		port = 636
		if o.Mode == "asrep" {
			port = 389
		}
	}
	if o.Mode != "dns" && o.Mode != "windows" && o.Mode != "sysvol" && o.Mode != "sysvol-auth" {
		limit := o.MaxObjects
		if limit == 0 {
			limit = 5000
		}
		lines = append(lines, fmt.Sprintf("LDAP port=%d connect_timeout=4s request_timeout=8s max_objects=%d", port, limit))
	}
	if o.Mode == "dns" {
		dnsPort, timeout := o.DNSPort, o.Timeout
		if dnsPort == 0 {
			dnsPort = 53
		}
		if timeout <= 0 {
			timeout = 8 * time.Second
		}
		lines = append(lines, fmt.Sprintf("DNS transport=tcp port=%d request_timeout=%s", dnsPort, timeout))
	}
	if o.Mode == "asrep" || o.Mode == "kerberoast" {
		timeout, rps := o.Timeout, o.RPS
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		if rps <= 0 {
			rps = 5
		}
		lines = append(lines, fmt.Sprintf("Kerberos users=%d SPNs=%d request_timeout=%s RPS=%d KDC=%s", len(o.Users), len(o.SPNs), timeout, rps, o.Host))
	}
	if o.Mode == "windows" {
		lines = append(lines, fmt.Sprintf("WinRM port=%d timeout=%s", o.WinRMPort, o.Timeout))
	}
	lines = append(lines, "Configured DNS servers: "+strings.Join(o.DNS.Servers, ", "), "Configured DNS domains: "+strings.Join(o.DNS.Domains, ", "))
	return lines
}
