package app

import (
	"context"
	"testing"

	"wscan/internal/adscan"
	"wscan/internal/domain"
)

func TestADKnownDialectsAndWindowsVersionAvoidInapplicableProbes(t *testing.T) {
	host := adscan.Host{Address: "10.0.0.10", Ports: []int{445, 3389}}
	facts := []domain.Finding{
		{TemplateID: "nmap/smb-protocols", Target: "10.0.0.10:445", Evidence: "dialects:\n  2.0.2\n  2.1\n  3.1.1"},
		{TemplateID: "nmap/rdp-ntlm-info", Target: "10.0.0.10:3389", Evidence: "Product_Version: 10.0.19041\nDNS_Computer_Name: DESKTOP"},
	}
	r := runADWindowsPlan(context.Background(), []adscan.Host{host}, false, nil, func(context.Context, adscan.Host, adWindowsCheck) (bool, error) {
		t.Fatal("known unavailable SMB1/legacy RDP check was sent")
		return false, nil
	}, adWindowsCapabilities(facts))
	if len(r.Errors) != 0 || len(r.Findings) != 0 || len(r.Skipped) != 7 {
		t.Fatalf("unexpected capability result: %+v", r)
	}
	// A Windows 7 target supporting SMB1 must still receive every regular probe.
	facts[0].Evidence = "dialects:\n  NT LM 0.12 (SMBv1) [dangerous, but default]\n  2.1"
	facts[1].Evidence = "Product_Version: 6.1.7601"
	calls := 0
	r = runADWindowsPlan(context.Background(), []adscan.Host{host}, false, nil, func(context.Context, adscan.Host, adWindowsCheck) (bool, error) { calls++; return false, nil }, adWindowsCapabilities(facts))
	if calls != 3 {
		t.Fatalf("Windows 7/SMB1 checks suppressed: %d", calls)
	}
}

func TestADCapabilityErrorsAndOtherHostsDoNotSuppressChecks(t *testing.T) {
	facts := []domain.Finding{{TemplateID: "nmap/smb-protocols", Target: "10.0.0.1:445", Evidence: "ERROR: negotiate failed"}, {TemplateID: "nmap/rdp-ntlm-info", Target: "10.0.0.2:3389", Evidence: "Product_Version: 10.0.19041"}}
	caps := adWindowsCapabilities(facts)
	for _, c := range adWindowsPlan(adscan.Host{Address: "10.0.0.1", Ports: []int{445, 3389}}) {
		if adWindowsCapabilitySkip(c, caps["10.0.0.1"]) != "" {
			t.Fatal("missing evidence was treated as absence of a vulnerable protocol")
		}
	}
}

func TestADMissingDomainIsSkipButDNSFailureRemainsError(t *testing.T) {
	errs, skipped := adDiagnosticStatus([]string{"DNS SRV пропущен: домен не раскрыт; укажите DNS-имя домена вручную.", "DNS 10.0.0.1: read timeout"})
	if len(errs) != 1 || len(skipped) != 1 {
		t.Fatal("coverage skip mixed with actual DNS error")
	}
}
