package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"wscan/internal/domain"
)

func TestCredentialCRUD(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "projects.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	projectID, err := s.CreateProject(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}

	id, err := s.CreateCredential(ctx, domain.Credential{
		ProjectID: projectID,
		Type:      "password",
		Username:  "jdoe",
		Domain:    "CORP",
		Secret:    "hunter2",
		Notes:     "found in leak",
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("expected non-zero credential id")
	}

	creds, err := s.ListCredentials(ctx, projectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	got := creds[0]
	if got.ID != id || got.ProjectID != projectID || got.Type != "password" || got.Username != "jdoe" || got.Domain != "CORP" || got.Secret != "hunter2" || got.Notes != "found in leak" {
		t.Fatalf("round-tripped credential mismatch: %+v", got)
	}

	// A second project must not see the first project's credentials.
	otherProjectID, err := s.CreateProject(ctx, "p2")
	if err != nil {
		t.Fatal(err)
	}
	otherCreds, err := s.ListCredentials(ctx, otherProjectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherCreds) != 0 {
		t.Fatalf("expected 0 credentials for unrelated project, got %d", len(otherCreds))
	}

	if err := s.DeleteCredential(ctx, id); err != nil {
		t.Fatal(err)
	}
	creds, err = s.ListCredentials(ctx, projectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 0 {
		t.Fatalf("expected 0 credentials after delete, got %d", len(creds))
	}
}

// TestRecentFailureCountIsLockoutSafe reproduces the exact property the
// spray engine (Phase 2) depends on: a domain account's lockout counter is
// shared across every target and protocol, so RecentFailureCount must count
// failures against a username project-wide, not per-host/per-protocol — an
// undercounted check here would let the spray loop push a real AD account
// over its lockout threshold.
func TestRecentFailureCountIsLockoutSafe(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "projects.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	projectID, err := s.CreateProject(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}

	since := time.Now().Add(-30 * time.Minute)

	// Two failures against "jdoe" on two different hosts, two different
	// protocols — both must count toward the same lockout window.
	if err := s.RecordAttempt(ctx, projectID, "10.0.0.1", "jdoe", "smb", false); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAttempt(ctx, projectID, "10.0.0.2", "jdoe", "ldap", false); err != nil {
		t.Fatal(err)
	}
	// A failure against a different username must not count toward jdoe's total.
	if err := s.RecordAttempt(ctx, projectID, "10.0.0.1", "asmith", "smb", false); err != nil {
		t.Fatal(err)
	}
	// A success must not count as a failure.
	if err := s.RecordAttempt(ctx, projectID, "10.0.0.3", "jdoe", "winrm", true); err != nil {
		t.Fatal(err)
	}

	n, err := s.RecentFailureCount(ctx, projectID, "jdoe", since)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("RecentFailureCount(jdoe) = %d, want 2 (failures across both hosts/protocols must both count)", n)
	}

	// A failure outside the observation window must not count.
	n, err = s.RecentFailureCount(ctx, projectID, "jdoe", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("RecentFailureCount(jdoe, future since) = %d, want 0", n)
	}
}
