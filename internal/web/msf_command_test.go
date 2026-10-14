package web

import (
	"encoding/json"
	"strings"
	"testing"

	"wscan/internal/domain"
)

func TestWebMSFCommandGenerationDoesNotStartTask(t *testing.T) {
	f := newWebFixture(t)
	for _, tc := range []struct {
		finding domain.Finding
		status  int
		module  string
	}{
		{domain.Finding{TemplateID: "adscan-smb-vuln-ms17-010", Severity: "critical", MatchedAt: "tcp://10.0.5.10:1445"}, 200, "exploit/windows/smb/ms17_010_eternalblue"},
		{domain.Finding{TemplateID: "nmap/rdp-vuln-ms12-020", Severity: "unknown", Target: "10.0.5.11:3389", MatchedAt: "nse://10.0.5.11:3389/rdp-vuln-ms12-020", Evidence: "State: VULNERABLE"}, 200, "auxiliary/scanner/rdp/ms12_020_check"},
		{domain.Finding{TemplateID: "adscan-smb-vuln-ms17-010", Severity: "critical", Target: "host; run"}, 400, ""},
		{domain.Finding{TemplateID: "unknown", Severity: "critical", Target: "10.0.5.10:445"}, 400, ""},
	} {
		r := f.request(t, "POST", "/api/commands/msf", tc.finding)
		var generated map[string]string
		err := json.NewDecoder(r.Body).Decode(&generated)
		r.Body.Close()
		if err != nil || r.StatusCode != tc.status {
			t.Fatalf("command response: status=%d error=%v body=%v", r.StatusCode, err, generated)
		}
		if tc.status == 200 && (!strings.Contains(generated["command"], tc.module) || generated["explanation"] == "") {
			t.Fatalf("incorrect generated command: %v", generated)
		}
	}
	if len(f.server.App.Jobs.List()) != 0 {
		t.Fatal("command generation started a task")
	}
	// The command route uses the same CSRF guard as the rest of the web API.
	f.csrf = ""
	r := f.request(t, "POST", "/api/commands/msf", domain.Finding{})
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Fatalf("command generation bypassed CSRF guard: %d", r.StatusCode)
	}
}
