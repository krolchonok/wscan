package domain

import (
	"regexp"
	"strings"
)

var vncNoAuthWarning = regexp.MustCompile(`(?im)^\s*WARNING:\s*Server does not require authentication\s*$`)

// EffectiveSeverity also corrects informational results saved by older builds.
// Only vnc-info's specific security-negotiation warning qualifies, not a
// banner, description, or an arbitrary script containing the same words.
func EffectiveSeverity(f Finding) string {
	severity := strings.ToLower(strings.TrimSpace(f.Severity))
	if f.TemplateID == "nmap/vnc-info" && severity != "error" &&
		!strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.Evidence)), "error:") &&
		vncNoAuthWarning.MatchString(f.Evidence) {
		return "critical"
	}
	return severity
}
