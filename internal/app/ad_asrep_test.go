package app

import (
	"strings"
	"testing"

	"wscan/internal/adscan"
)

func TestASREPFindingsRetainHashesAndFoldNormalReplies(t *testing.T) {
	report := adscan.AccessReport{Host: "192.0.2.10", Endpoint: "tcp://192.0.2.10:8888", Mode: "asrep", Checks: []adscan.AccessCheck{
		{ID: "asrep/alice", Name: "alice", State: "confirmed", Severity: "high", Evidence: "$krb5asrep$23$alice@LAB.EXAMPLE:0123$4567"},
		{ID: "asrep/bob", Name: "bob", State: "negative", Severity: "info", Evidence: "preauth required"},
		{ID: "asrep/carol", Name: "carol", State: "denied", Severity: "info", Evidence: "revoked"},
		{ID: "asrep/dave", Name: "dave", State: "error", Severity: "info", Evidence: "timeout"},
	}, Artifacts: []string{"/tmp/asrep.hashcat"}}
	findings := ASREPReportFindings(report)
	if len(findings) != 4 {
		t.Fatalf("normal replies clutter results: %+v", findings)
	}
	if findings[0].Severity != "high" || findings[0].MatchedAt != report.Endpoint || !strings.Contains(findings[0].Evidence, "$krb5asrep$") {
		t.Fatal(findings[0])
	}
	if findings[1].Severity != "info" || !strings.Contains(findings[1].Evidence, "timeout") {
		t.Fatal("network error became vulnerability")
	}
	if !strings.Contains(findings[2].Evidence, "Проверено имён: 4") || !strings.Contains(findings[2].Evidence, "AS-REP: 1") {
		t.Fatal(findings[2])
	}
	if findings[3].MatchedAt != report.Endpoint || !strings.Contains(findings[3].Evidence, "asrep.hashcat") {
		t.Fatal("lost export")
	}
}
