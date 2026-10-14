// Package commandgen formats commands for manual use in external tools.
package commandgen

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"wscan/internal/domain"
	"wscan/internal/nse"
)

// Only curated finding IDs select a module. Target-controlled descriptions,
// references and evidence never become console commands or module names.
func MSF(f domain.Finding) (command, explanation string, ok bool) {
	severity := domain.EffectiveSeverity(f)
	isNSE := strings.HasPrefix(f.TemplateID, "nmap/")
	if severity == "error" || strings.EqualFold(f.Protocol, "udp") ||
		(isNSE && nse.OutputIsError(f.Evidence)) ||
		((severity == "" || severity == "info") && !(isNSE && nse.OutputSeverity(f.Evidence) == "unknown")) {
		return "", "", false
	}
	id := strings.ToLower(path.Base(f.TemplateID))
	id = strings.TrimSuffix(strings.TrimSuffix(id, ".yaml"), ".nse")
	var module, options string
	var port int
	switch id {
	case "adscan-smb-vuln-ms17-010", "smb-vuln-ms17-010", "cve-2017-0143", "cve-2017-0144":
		module, port = "exploit/windows/smb/ms17_010_eternalblue", 445
		options = "; set PAYLOAD windows/x64/meterpreter/reverse_tcp"
		explanation = "EternalBlue: шаблон получения сессии для Windows x64. Проверьте архитектуру Windows. Проверка MS17-010 не гарантирует получение сессии; эксплуатация может вызвать сбой или перезагрузку."
	case "adscan-ms12-020", "rdp-vuln-ms12-020", "msf-rdp-ms12-020-check":
		module, port = "auxiliary/scanner/rdp/ms12_020_check", 3389
		explanation = "Повторная проверка MS12-020 через Metasploit. Это проверочный модуль; получение RCE он не реализует."
	default:
		return "", "", false
	}
	address := f.MatchedAt
	if address == "" {
		address = f.Target
	}
	// NSE stores the matched endpoint with the script ID in the URL path.
	if isNSE && strings.HasPrefix(address, "nse://") {
		u, err := url.Parse(address)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/"+id {
			return "", "", false
		}
		address = "tcp://" + u.Host
	}
	host, port, ok := msfCommandEndpoint(address, port)
	if !ok {
		return "", "", false
	}
	// Host validation below protects both the shell and the msfconsole parser.
	console := fmt.Sprintf("use %s; set RHOSTS %s; set RPORT %d%s; run", module, host, port, options)
	return "msfconsole -q -x '" + console + "'", explanation, true
}

func msfCommandEndpoint(address string, defaultPort int) (string, int, bool) {
	host, port := address, defaultPort
	if strings.Contains(address, "://") {
		u, err := url.Parse(address)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(u.Host, ":") || (u.Path != "" && u.Path != "/") {
			return "", 0, false
		}
		switch u.Scheme {
		case "tcp", "smb", "rdp":
		default:
			return "", 0, false
		}
		host = u.Hostname()
		if u.Port() != "" {
			port, err = strconv.Atoi(u.Port())
			if err != nil {
				return "", 0, false
			}
		}
	} else if h, p, err := net.SplitHostPort(address); err == nil {
		host = h
		port, err = strconv.Atoi(p)
		if err != nil {
			return "", 0, false
		}
	}
	if port < 1 || port > 65535 || !msfCommandHost(host) {
		return "", 0, false
	}
	return host, port, true
}

func msfCommandHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
