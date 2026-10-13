package app

import (
	"strings"
	"testing"

	"wscan/internal/adscan"
	"wscan/internal/domain"
	"wscan/internal/nse"
)

func TestADMS17010ResultHasSeverityEndpointAndSummary(t *testing.T) {
	host := adscan.Host{Address: "10.0.0.123", Ports: []int{445}}
	f := adAnonymousFinding(host, nse.ScriptResult{ScriptID: "smb-vuln-ms17-010", Output: "VULNERABLE:\nMS17-010\nState: VULNERABLE\nIDs: CVE:CVE-2017-0143"})
	if f.Severity != "critical" || f.Target != "10.0.0.123:445" || f.MatchedAt != "nse://10.0.0.123:445/smb-vuln-ms17-010" {
		t.Fatalf("lost vulnerability classification or SMB endpoint: %+v", f)
	}
	summary := adReconSummary("10.0.0.0/24", adscan.Result{Hosts: []adscan.Host{host}}, []domain.Finding{f})
	if !strings.Contains(summary.Evidence, "риск-находки: 1") || !strings.Contains(summary.Evidence, "Высший приоритет") {
		t.Fatalf("critical vulnerability missing from AD summary: %s", summary.Evidence)
	}
	patched := adAnonymousFinding(host, nse.ScriptResult{ScriptID: "smb-vuln-ms17-010", Output: "State: NOT VULNERABLE"})
	if patched.Severity != "info" || strings.Contains(patched.Name, "уязвимый") {
		t.Fatal("patched response was classified as vulnerable")
	}
	unknown := adAnonymousFinding(host, nse.ScriptResult{ScriptID: "smb-vuln-ms17-010", Output: "Could not establish connection"})
	if unknown.Severity == "critical" {
		t.Fatal("connection failure was classified as vulnerable")
	}
}

func TestADAnonymousScriptsFollowDiscoveredServices(t *testing.T) {
	for _, port := range []int{139, 445} {
		scripts := strings.Join(adAnonymousScripts([]int{port}), "\n")
		for _, id := range []string{"smb-double-pulsar-backdoor.nse", "smb2-security-mode.nse"} {
			if !strings.Contains(scripts, id) {
				t.Fatalf("SMB/%d does not include %s", port, id)
			}
		}
		if strings.Contains(scripts, "smb-vuln-ms17-010.nse") != (port == 139) {
			t.Fatal("MS17-010 duplicated on 445 or missing on NetBIOS-only host")
		}
	}
	if scripts := strings.Join(adAnonymousScripts([]int{3389}), "\n"); !strings.Contains(scripts, "rdp-ntlm-info.nse") || strings.Contains(scripts, "smb-") {
		t.Fatal("RDP checks do not match the discovered service")
	}
	if len(adAnonymousScripts([]int{80, 53})) != 0 {
		t.Fatal("SMB vulnerability checks selected for unrelated services")
	}
	f := adAnonymousFinding(adscan.Host{Address: "10.0.0.16", Ports: []int{139}}, nse.ScriptResult{ScriptID: "smb-os-discovery", Output: "OS: Windows"})
	if f.Target != "10.0.0.16:139" || f.Severity != "info" {
		t.Fatal("SMB/139 discovery mapped to the wrong endpoint or severity")
	}
}
