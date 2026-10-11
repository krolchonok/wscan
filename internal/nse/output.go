package nse

import (
	"regexp"
	"strings"

	"wscan/internal/domain"
)

// vulnerableStateRE matches the "VULNERABLE" state line emitted by nmap's vuln
// library, so a script's output can be surfaced as a risk rather than info.
var vulnerableStateRE = regexp.MustCompile(`(?im)^\s*(?:state:\s*)?vulnerable\s*:?\s*$`)

// HasServiceRule reports whether an NSE script has a portrule/hostrule and thus
// runs against the selected host/port.
func HasServiceRule(source []byte) bool {
	rules, err := declaredRules(source)
	return err == nil && (rules["portrule"] || rules["hostrule"])
}

// OutputSeverity classifies saved NSE output. A "vulnerable" state is surfaced
// as a risk ("unknown" severity, since NSE output is not CVSS-graded); anything
// else is informational.
func OutputSeverity(output string) string {
	if vulnerableStateRE.MatchString(output) {
		return "unknown"
	}
	return "info"
}

// ScriptSeverity preserves informational discovery output while surfacing
// script-specific security findings in both CLI and TUI scans.
func ScriptSeverity(scriptID, output string) string {
	return domain.EffectiveSeverity(domain.Finding{
		TemplateID: "nmap/" + scriptID, Severity: OutputSeverity(output), Evidence: output,
	})
}

// OutputIsError reports whether saved NSE output is an error message rather than
// a result. Soft protocol failures that are not actionable (e.g. SMBv1 negotiate
// against an SMB2-only host) are treated as noise instead — see OutputIsNoise.
func OutputIsError(output string) bool {
	if OutputIsNoise("", output) {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(output))
	return strings.HasPrefix(s, "error:") ||
		strings.HasPrefix(s, "error ") ||
		strings.HasPrefix(s, "script execution failed") ||
		strings.HasPrefix(s, "couldn't establish connection on port ") ||
		strings.HasPrefix(s, "could not establish connection on port ") ||
		strings.HasPrefix(s, "smtp failed to send ") ||
		strings.HasPrefix(s, "smtp ") && strings.Contains(s, ": failed to receive data:")
}

// OutputIsNoise reports informational NSE output that is not a useful finding
// (missing API key, empty page title, SMB negotiate soft-fails, and similar).
func OutputIsNoise(scriptID, output string) bool {
	s := strings.ToLower(strings.TrimSpace(output))
	if s == "" {
		return true
	}
	id := strings.ToLower(scriptID)
	if strings.Contains(s, "no api key") {
		return true
	}
	if strings.Contains(s, "doesn't have a title") || strings.Contains(s, "site doesn't have a title") {
		return true
	}
	// Defensive: some runners store "script: message" forms.
	if strings.Contains(id, "http-google-malware") && strings.Contains(s, "api key") {
		return true
	}
	if strings.Contains(id, "http-title") && (s == "site doesn't have a title." || strings.HasPrefix(s, "site doesn't have a title")) {
		return true
	}
	if strings.Contains(s, "script-args") && strings.Contains(s, "is required") {
		return true
	}
	// SMBv1 path failing against SMB2+/dialect-only hosts: nmap smb.lua cannot
	// finish negotiate, so almost every smb-enum-* script emits this. Real
	// dialect info already comes from smb-protocols / smb2-* scripts.
	if strings.Contains(s, "could not negotiate a connection") {
		return true
	}
	if strings.Contains(s, "server returned less data than it was supposed to") {
		return true
	}
	if strings.Contains(s, "failed to connect to browser service") {
		return true
	}
	return false
}
