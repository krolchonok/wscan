package domain

import "testing"

func TestVNCSeverityRequiresScriptWarning(t *testing.T) {
	for _, tc := range []struct{ id, severity, evidence, want string }{
		{"nmap/vnc-info", "info", "Protocol version: 3.8\nWARNING: Server does not require authentication", "critical"},
		{"nmap/vnc-info", "info", "  WARNING: Server does not require authentication\r\n", "critical"},
		{"nmap/vnc-info", "info", "Protocol version: 3.8\nSecurity types: VNC Authentication (2)", "info"},
		{"nmap/vnc-info", "info", "Security types: None (1)", "info"},
		{"nmap/http-title", "info", "WARNING: Server does not require authentication", "info"},
		{"nmap/vnc-info", "info", "Description: Server does not require authentication", "info"},
		{"nmap/vnc-info", "error", "WARNING: Server does not require authentication", "error"},
		{"nmap/vnc-info", "info", "ERROR: handshake failed\nWARNING: Server does not require authentication", "info"},
	} {
		if got := EffectiveSeverity(Finding{TemplateID: tc.id, Severity: tc.severity, Evidence: tc.evidence}); got != tc.want {
			t.Errorf("%q %q: got %q want %q", tc.id, tc.evidence, got, tc.want)
		}
	}
}
