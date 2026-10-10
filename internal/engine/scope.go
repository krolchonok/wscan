package engine

import (
	"net"
	"net/url"
	"strings"

	"wscan/internal/domain"
)

// targetsAreAllIPs reports whether every scan target is an IP address (or a
// URL whose host is an IP). Used to drop checks that only make sense for
// domain names (cloud config, DNS, takeovers).
func targetsAreAllIPs(targets []string) bool {
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		host := targetHostname(t)
		if host == "" || net.ParseIP(host) == nil {
			return false
		}
	}
	return true
}

func targetHostname(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	// host:port or bare host
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}
	return raw
}

// skipTemplateOnIPTarget drops templates that are wasted against bare IPs:
// cloud audits, DNS record checks, and subdomain-takeover detectors.
func skipTemplateOnIPTarget(t domain.Template) bool {
	src := strings.ToLower(strings.ReplaceAll(t.Source, "\\", "/"))
	if strings.HasPrefix(src, "cloud/") || strings.HasPrefix(src, "dns/") {
		return true
	}
	if strings.Contains(src, "takeover") {
		return true
	}
	id := strings.ToLower(t.ID)
	if strings.Contains(id, "takeover") || strings.Contains(id, "dns-") {
		return true
	}
	return false
}
