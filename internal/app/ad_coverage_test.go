package app

import (
	"strings"
	"testing"
	"wscan/internal/domain"
)

func TestSAMRNamesKeepCorrectDomain(t *testing.T) {
	for _, output := range []string{`Domain: LAB; Users: alice, bob, CLIENT2$`, `LAB\alice (RID: 1100)
LAB\bob (RID: 1101)
OTHER\wrong (RID: 1200)`} {
		users := samrNames(output, "LAB")
		if len(users) != 2 {
			t.Fatal(users)
		}
	}
	if names := samrNames("SAMR returned NT_STATUS_ACCESS_DENIED", "LAB"); len(names) != 0 {
		t.Fatal(names)
	}
}
func TestCoverageDoesNotPromoteTimeoutToNegative(t *testing.T) {
	r := adCoverageFindings("lab", []domain.CheckCoverage{{Host: "client", CheckID: "bluekeep", State: "error", Evidence: "timeout"}, {Host: "client", CheckID: "dns-axfr", State: "denied", Evidence: "refused"}})
	if len(r) != 1 || r[0].Severity != "info" {
		t.Fatal(r)
	}
}

func TestCoveragePromotesAnonymousSAMRDetails(t *testing.T) {
	output := "LAB\\\\alice (RID: 1100)\n  Full name: Alice Smith\n  Description: Backup operator"
	findings := adCoverageFindings("10.0.0.0/24", []domain.CheckCoverage{{Host: "10.0.0.10", Port: 445, CheckID: "samr-users", State: "observed", Evidence: output}})
	var got *domain.Finding
	for i := range findings {
		if findings[i].TemplateID == "adscan-samr-users" {
			got = &findings[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("SAMR finding missing: %+v", findings)
	}
	if got.Severity != "low" || !strings.Contains(got.Description, "Backup operator") {
		t.Fatalf("SAMR details lost: %+v", got)
	}
}

func TestCoveragePromotesAnonymousSAMRGroups(t *testing.T) {
	output := `LAB\\Domain Admins (RID: 512): Administrator, alice`
	findings := adCoverageFindings("10.0.0.0/24", []domain.CheckCoverage{{Host: "10.0.0.10", Port: 445, CheckID: "samr-groups", State: "observed", Evidence: output}})
	for _, finding := range findings {
		if finding.TemplateID == "adscan-samr-groups" && finding.Severity == "low" && strings.Contains(finding.Description, "Domain Admins") {
			return
		}
	}
	t.Fatalf("SAMR groups finding missing: %+v", findings)
}

func TestCoveragePromotesAnonymousSAMRDomainPolicy(t *testing.T) {
	output := "LAB\nPasswords: min length: 12; history: 24 passwords\nAccount lockout: 5 attempts"
	findings := adCoverageFindings("10.0.0.0/24", []domain.CheckCoverage{{Host: "10.0.0.10", Port: 445, CheckID: "samr-domain-policy", State: "observed", Evidence: output}})
	for _, finding := range findings {
		if finding.TemplateID == "adscan-samr-domain-policy" && strings.Contains(finding.Description, "min length: 12") {
			return
		}
	}
	t.Fatalf("SAMR domain policy finding missing: %+v", findings)
}

func TestSMBIdentityDNSDomainFallback(t *testing.T) {
	if got := smbIdentityDNSDomain("", "LAB.Example."); got != "lab.example" {
		t.Fatalf("forest fallback = %q", got)
	}
	if got := smbIdentityDNSDomain("ad.lab.example", "other.example"); got != "ad.lab.example" {
		t.Fatalf("DNS domain priority = %q", got)
	}
}
