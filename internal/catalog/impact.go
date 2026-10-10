package catalog

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ImpactDiscovery = "Обнаружение"
	ImpactActive    = "Активные проверки"
	ImpactStrong    = "Сильное воздействие"
)

// Impact is a conservative metadata classification, not a guarantee that a
// check has no side effects. All three levels can send requests to the target.
func Impact(e Entry) string {
	if e.Impact != "" {
		return e.Impact
	}
	return ImpactActive
}

func classifyImpact(e Entry, source []byte) string {
	tags := strings.ToLower(e.Category)
	path := strings.ToLower(e.Path)
	if !strings.HasPrefix(e.Path, "nmap/") {
		var root map[string]any
		if yaml.Unmarshal(source, &root) == nil {
			info, _ := root["info"].(map[string]any)
			tags = strings.ToLower(fmt.Sprint(info["tags"]))
			if root["code"] != nil {
				return ImpactStrong
			}
			if requests, ok := root["http"].([]any); ok {
				for _, req := range requests {
					if fields, ok := req.(map[string]any); ok {
						if fields["fuzzing"] != nil || fields["payloads"] != nil {
							return ImpactStrong
						}
					}
				}
			}
		}
	}
	if strings.Contains(path, "/default-logins/") || strings.Contains(path, "/default-login/") ||
		strings.Contains(path, "/credential-stuffing/") || strings.Contains(path, "wp-xmlrpc-brute-force") {
		return ImpactStrong
	}
	tokens := strings.FieldsFunc(tags, func(r rune) bool { return r == ',' || r == ' ' || r == '[' || r == ']' })
	set := map[string]bool{}
	for _, tag := range tokens {
		set[tag] = true
	}
	for _, tag := range []string{"dos", "intrusive", "exploit", "brute", "bruteforce", "creds-stuffing", "credential-stuffing", "fuzzer", "fuzz", "fuzzing", "rce", "sqli", "ssti", "xxe", "deserialization", "race-condition", "upload", "xss", "ssrf"} {
		if set[tag] {
			return ImpactStrong
		}
	}
	if strings.HasPrefix(e.Path, "dast/") {
		return ImpactStrong
	}
	for _, tag := range []string{"vuln", "cve", "auth-bypass", "auth", "credentials", "intrusion"} {
		if set[tag] {
			return ImpactActive
		}
	}
	for _, tag := range []string{"discovery", "version", "tech", "panel", "panels", "detect", "detection", "fingerprint"} {
		if set[tag] {
			return ImpactDiscovery
		}
	}
	return ImpactActive
}
