package app

import (
	"strings"
	"testing"

	"wscan/internal/adscan"
)

func TestASREPFindingsRetainHashesAndFoldNormalReplies(t *testing.T) {
	report := adscan.AccessReport{Host: "192.0.2.10", Endpoint: "tcp://192.0.2.10:8888", Mode: "asrep", Checks: []adscan.AccessCheck{
		{ID: "asrep/alice", Name: "alice", State: "confirmed", Severity: "high", Evidence: "$krb5asrep$23$alice@LAB.EXAMPLE:0123$4567"},
		{ID: "asrep/bob", Name: "bob", State: "valid", Severity: "info", Evidence: "preauth required"},
		{ID: "asrep/carol", Name: "carol", State: "valid-disabled", Severity: "info", Evidence: "revoked"},
		{ID: "asrep/nobody", Name: "nobody", State: "negative", Severity: "info", Evidence: "unknown principal"},
		{ID: "asrep/dave", Name: "dave", State: "error", Severity: "info", Evidence: "timeout"},
	}, Artifacts: []string{"/tmp/asrep.hashcat"}}
	findings := ASREPReportFindings(report)
	if len(findings) != 5 {
		t.Fatalf("normal replies clutter results: %+v", findings)
	}
	if findings[0].Severity != "high" || findings[0].MatchedAt != report.Endpoint || !strings.Contains(findings[0].Evidence, "$krb5asrep$") {
		t.Fatal(findings[0])
	}
	if findings[1].Severity != "info" || !strings.Contains(findings[1].Evidence, "timeout") {
		t.Fatal("network error became vulnerability")
	}
	if !strings.Contains(findings[2].Evidence, "Проверено имён: 5") || !strings.Contains(findings[2].Evidence, "существующие с pre-auth: 1") || !strings.Contains(findings[2].Evidence, "AS-REP: 1") {
		t.Fatal(findings[2])
	}
	if !strings.Contains(findings[3].Evidence, "bob") || !strings.Contains(findings[3].Evidence, "carol") {
		t.Fatal("lost enumerated identities")
	}
	if findings[4].MatchedAt != report.Endpoint || !strings.Contains(findings[4].Evidence, "asrep.hashcat") {
		t.Fatal("lost export")
	}
}
