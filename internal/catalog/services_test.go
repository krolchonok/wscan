package catalog

import (
	"testing"

	"wscan/internal/domain"
)

func TestTokenHitRejectsSambar(t *testing.T) {
	parts := splitTokens("sambar-ftp-detect")
	if tokenHit(parts, "samba") {
		t.Fatalf("sambar must not match samba: %v", parts)
	}
	if tokenHit(parts, "smb") {
		t.Fatalf("sambar must not match smb: %v", parts)
	}
	if serviceDirection("sambar-ftp-detect") == "SMB" {
		t.Fatal("sambar-ftp-detect classified as SMB")
	}
}

func TestTokenHitSMB(t *testing.T) {
	for _, name := range []string{"smb-os-discovery", "smb2-capabilities", "samba-vuln-cve-2012-1182"} {
		if serviceDirection(name) != "SMB" {
			t.Fatalf("%s => %s, want SMB", name, serviceDirection(name))
		}
	}
}

// TestServiceDirectionRecognizesMicrosoftDS reproduces a real regression:
// internal/discovery/smb_identify.go's active SMB probe names ANY port it
// recognizes as SMB2 "microsoft-ds" (nmap's own convention for the SMB
// port), including port 445 itself — overwriting the static "smb" preset
// that serviceDirection's token list already handled. Since splitTokens
// breaks the hyphenated name into "microsoft"/"ds" (neither a registered
// token), and name is non-empty so the "service not yet identified" port
// fallback never kicks in either, a discovered "microsoft-ds" service fell
// through to "Прочие сервисы" instead of "SMB" — the user-visible symptom
// being the TUI's "jump to this service's checks" action missing the SMB
// category entirely for a service our own scanner just identified as SMB.
func TestServiceDirectionRecognizesMicrosoftDS(t *testing.T) {
	for _, port := range []int{445, 4445} {
		s := domain.Service{Name: "microsoft-ds", Port: port}
		if got := ServiceDirection(s); got != "SMB" {
			t.Fatalf("ServiceDirection(microsoft-ds, port %d) = %q, want SMB", port, got)
		}
	}
}

func TestDirectionPrefersServiceField(t *testing.T) {
	e := Entry{Path: "network/detection/ftp/sambar-ftp-detect.yaml", Service: "FTP"}
	if Direction(e) != "FTP" {
		t.Fatalf("got %s", Direction(e))
	}
}

func TestDirectionUnsupportedBucket(t *testing.T) {
	e := Entry{
		Path: "dast/vulnerabilities/ssti/smarty-ssti.yaml", Service: "Web",
		Checked: true, Available: false, Reason: `http[0] field "fuzzing" is not supported`,
	}
	if !IsUnsupported(e) {
		t.Fatal("expected unsupported")
	}
	if Direction(e) != UnsupportedGroup {
		t.Fatalf("got %q want %q", Direction(e), UnsupportedGroup)
	}
	// Compatible templates keep their service.
	ok := Entry{Path: "http/technologies/tech-detect.yaml", Service: "Web", Checked: true, Available: true}
	if Direction(ok) != "Web" {
		t.Fatalf("got %s", Direction(ok))
	}
}

func TestWinRMServiceGrouping(t *testing.T) {
	for _, s := range []domain.Service{
		{Name: "winrm", Port: 5985},
		{Name: "winrm-https", Port: 5986},
		{Name: "wsman", Port: 15985},
		{Name: "wsmans", Port: 15986},
		{Name: "winrm-http", Port: 15985},
		{Name: "unknown", Port: 5985},
		{Name: "", Port: 5986},
	} {
		if got := ServiceDirection(s); got != "WinRM" {
			t.Fatalf("ServiceDirection(%+v) = %q, want WinRM", s, got)
		}
	}
	if got := ServiceDirection(domain.Service{Name: "ssh", Port: 5985}); got != "SSH" {
		t.Fatalf("identified SSH must take precedence over port hint: %q", got)
	}
	if got := Direction(Entry{Path: "http/technologies/winrm-detect.yaml"}); got != "WinRM" {
		t.Fatalf("fallback grouping without index = %q", got)
	}
}
