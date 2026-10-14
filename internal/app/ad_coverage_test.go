package app

import (
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
