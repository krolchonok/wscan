package catalog

import (
	"path/filepath"
	"strings"
	"unicode"

	"wscan/internal/domain"
)

// UnsupportedGroup is the catalog bucket for templates the native engine
// cannot run (or that are out of network/host scope). They are listed here
// instead of under Web/SMB/… so available counts stay honest.
const UnsupportedGroup = "Неподдерживаемые"

// IsUnsupported reports that a catalog entry has been checked and is not
// runnable by the native engine (or is out of scan scope).
func IsUnsupported(e Entry) bool {
	return e.Checked && !e.Available
}

// Direction groups by transport/service, independent of product and check type.
func Direction(e Entry) string {
	if IsUnsupported(e) {
		return UnsupportedGroup
	}
	if e.Service != "" {
		return e.Service
	}
	p := strings.ToLower(e.Path)
	if tokenHit(splitTokens(p), "winrm") || tokenHit(splitTokens(p), "wsman") || tokenHit(splitTokens(p), "wsmans") {
		return "WinRM"
	}
	for _, prefix := range []string{"http/", "headless/", "dast/"} {
		if strings.HasPrefix(p, prefix) {
			return "Web"
		}
	}
	if strings.HasPrefix(p, "ssl/") {
		return "TLS / SSL"
	}
	if strings.HasPrefix(p, "dns/") {
		return "DNS"
	}
	if strings.HasPrefix(p, "file/") {
		return "Файлы"
	}
	if strings.HasPrefix(p, "cloud/") {
		return "Облако"
	}
	name := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
	if strings.HasPrefix(p, "network/detection/ftp/") || strings.HasPrefix(name, "ftp-") || strings.Contains(name, "-ftp-") {
		return "FTP"
	}
	if strings.HasPrefix(name, "http-") || strings.HasPrefix(name, "https-") {
		return "Web"
	}
	if strings.HasPrefix(name, "ssl-") || strings.HasPrefix(name, "tls-") {
		return "TLS / SSL"
	}
	return serviceDirection(name + " " + strings.ToLower(e.Product))
}

func serviceDirection(name string) string {
	groups := []struct {
		title  string
		tokens []string
	}{
		{"WinRM", []string{"winrm", "wsman", "wsmans"}},
		{"SMB", []string{"smb", "smb2", "samba", "cifs"}},
		{"SSH", []string{"ssh", "ssh2"}},
		{"FTP", []string{"ftp", "tftp"}},
		{"RDP", []string{"rdp"}},
		{"DNS", []string{"dns", "dnssec"}},
		{"Почта", []string{"smtp", "imap", "pop3", "pop"}},
		{"Базы данных", []string{"mysql", "mssql", "ms-sql", "postgres", "redis", "mongo", "oracle", "cassandra", "couchdb", "memcached"}},
		{"LDAP", []string{"ldap"}},
		{"SNMP", []string{"snmp"}},
		{"VPN", []string{"ike", "ipsec", "openvpn", "pptp", "wireguard"}},
		{"RPC / Windows", []string{"rpc", "netbios", "msrpc"}},
		{"VNC", []string{"vnc"}},
		{"Telnet", []string{"telnet"}},
		{"Контейнеры", []string{"docker", "kubernetes", "kubelet"}},
	}
	parts := splitTokens(name)
	for _, g := range groups {
		for _, token := range g.tokens {
			if tokenHit(parts, token) {
				return g.title
			}
		}
	}
	return "Прочие сервисы"
}

func splitTokens(name string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		out = append(out, b.String())
		b.Reset()
	}
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return out
}

// tokenHit matches whole path parts only. "samba" does not match "sambar";
// numbered variants like smb2 match token smb.
func tokenHit(parts []string, token string) bool {
	for _, p := range parts {
		if p == token {
			return true
		}
		if strings.HasPrefix(p, token) && isAllDigits(p[len(token):]) {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func ServiceDirection(s domain.Service) string {
	name := strings.ToLower(s.Name)
	if domain.ServiceDatabase(s) != "" {
		return "Базы данных"
	}
	if tokenHit(splitTokens(name), "winrm") || tokenHit(splitTokens(name), "wsman") || tokenHit(splitTokens(name), "wsmans") {
		return "WinRM"
	}
	if strings.Contains(name, "http") {
		return "Web"
	}
	// "microsoft-ds" (the IANA/nmap name for the SMB port, and what our own
	// active SMB probe — internal/discovery/smb_identify.go's identifySMB —
	// now names ANY port it recognizes as SMB2, including 445 itself,
	// overwriting the static "smb" preset) never matches serviceDirection's
	// token list below: splitTokens breaks the hyphenated name into
	// "microsoft"/"ds", neither of which is a registered SMB token. Checked
	// explicitly here, the same way "http" is just above, rather than as a
	// token (which would need every other hyphenated/compound service name
	// handled the same way for no real benefit).
	if strings.Contains(name, "microsoft-ds") {
		return "SMB"
	}
	if d := serviceDirection(name); d != "Прочие сервисы" {
		return d
	}
	// Port numbers are only hints when discovery did not identify the service.
	if name != "" && name != "unknown" {
		return "Прочие сервисы"
	}
	switch s.Port {
	case 80, 443, 8000, 8080, 8443, 8888:
		return "Web"
	case 5985, 5986:
		return "WinRM"
	case 139, 445:
		return "SMB"
	case 22:
		return "SSH"
	case 21:
		return "FTP"
	case 3389:
		return "RDP"
	case 53:
		return "DNS"
	case 25, 110, 143, 465, 587, 993, 995:
		return "Почта"
	}
	return "Прочие сервисы"
}
