package storage

import (
	"context"
	"path/filepath"
	"testing"

	"wscan/internal/domain"
)

func TestLoadOldVNCFindingCorrectsSeverityWithoutChangingEvidence(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "projects.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := s.CreateProject(ctx, "vnc")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := s.StartRun(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	const evidence = "WARNING: Server does not require authentication"
	if err := s.SaveFinding(ctx, runID, domain.Finding{TemplateID: "nmap/vnc-info", Severity: "info", Evidence: evidence}); err != nil {
		t.Fatal(err)
	}
	findings, err := s.Findings(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Severity != "critical" || findings[0].Evidence != evidence {
		t.Fatalf("incorrect stored result: %+v", findings)
	}
}
