package storage

import (
	"context"
	"path/filepath"
	"testing"

	"wscan/internal/domain"
)

func TestOpenRemovesLegacyProfilesAndPreservesData(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "projects.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"projects", "runs"} {
		if _, err := s.db.Exec("ALTER TABLE " + table + " ADD COLUMN profile TEXT NOT NULL DEFAULT 'read-only'"); err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.CreateProject(ctx, "existing project")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddTarget(ctx, id, "localhost"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTemplates(ctx, id, []string{"selected-check"}, true); err != nil {
		t.Fatal(err)
	}
	runID, err := s.StartRun(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveFinding(ctx, runID, domain.Finding{TemplateID: "selected-check"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveService(ctx, runID, domain.Service{Host: "localhost", Port: 80}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, table := range []string{"projects", "runs"} {
		var count int
		if err := s.db.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name='profile'`, table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s still contains a profile: count=%d, err=%v", table, count, err)
		}
	}
	projects, err := s.ListProjects(ctx)
	if err != nil || len(projects) != 1 || len(projects[0].Targets) != 1 || len(projects[0].TemplateIDs) != 1 {
		t.Fatalf("project data was lost: %+v, err=%v", projects, err)
	}
	runs, err := s.Runs(ctx, id)
	if err != nil || len(runs) != 1 || len(runs[0].Findings) != 1 || len(runs[0].Services) != 1 {
		t.Fatalf("run data was lost: %+v, err=%v", runs, err)
	}
	if _, err := s.StartRun(ctx, id); err != nil {
		t.Fatalf("cannot start a run after migration: %v", err)
	}
}

func TestRestoreInventoryHostAdvancesWatermark(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "projects.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := s.CreateProject(ctx, "restore-host")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := s.StartRun(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, runID, "completed"); err != nil {
		t.Fatal(err)
	}
	if err := s.ExcludeInventory(ctx, id, "10.0.0.10", "", nil, []string{"10.0.0.10"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreInventoryHost(ctx, id, "10.0.0.10"); err != nil {
		t.Fatal(err)
	}
	resets, err := s.InventoryResets(ctx, id)
	if err != nil || len(resets) != 1 || resets[0].ThroughRun != runID {
		t.Fatalf("restore should keep watermark at current max run: %+v err=%v", resets, err)
	}
	exclusions, err := s.InventoryExclusions(ctx, id)
	if err != nil || len(exclusions) != 0 {
		t.Fatalf("restore should clear exclusions: %+v err=%v", exclusions, err)
	}
}

func TestOpenDropsStaleInventoryResets(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "projects.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateProject(ctx, "stale-reset")
	if err != nil {
		t.Fatal(err)
	}
	runID, err := s.StartRun(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, runID, "completed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO inventory_resets(project_id,host,through_run,aliases) VALUES(?,?,?,'["10.0.0.10"]')`, id, "10.0.0.10", runID+100); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resets, err := s.InventoryResets(ctx, id)
	if err != nil || len(resets) != 0 {
		t.Fatalf("stale watermark above max run id should be dropped: %+v err=%v", resets, err)
	}
}

func TestAllowCodeExecRoundTripAndMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "projects.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateProject(ctx, "code-exec-project")
	if err != nil {
		t.Fatal(err)
	}
	projects, err := s.ListProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var p domain.Project
	for _, x := range projects {
		if x.ID == id {
			p = x
		}
	}
	if p.AllowCodeExec {
		t.Fatalf("new project must default allow_code_exec to false")
	}
	p.AllowCodeExec = true
	if err := s.SetProjectScanSettings(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening must also work against a database created before this column
	// existed — the same path TestOpenRemovesLegacyProfilesAndPreservesData
	// exercises for the "profile" column removal, here for the "add column"
	// direction instead.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	projects, err = s.ListProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range projects {
		if x.ID == id {
			found = true
			if !x.AllowCodeExec {
				t.Fatalf("allow_code_exec did not round-trip: got false, want true")
			}
		}
	}
	if !found {
		t.Fatalf("project %d not found after reopen", id)
	}
}

func TestAllowExploitRoundTripAndMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "projects.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateProject(ctx, "exploit-project")
	if err != nil {
		t.Fatal(err)
	}
	projects, err := s.ListProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var p domain.Project
	for _, x := range projects {
		if x.ID == id {
			p = x
		}
	}
	if p.AllowExploit {
		t.Fatalf("new project must default allow_exploit to false")
	}
	p.AllowExploit = true
	if err := s.SetProjectScanSettings(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening must also work against a database created before this column
	// existed — same "add column" migration path as allow_code_exec above.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	projects, err = s.ListProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range projects {
		if x.ID == id {
			found = true
			if !x.AllowExploit {
				t.Fatalf("allow_exploit did not round-trip: got false, want true")
			}
		}
	}
	if !found {
		t.Fatalf("project %d not found after reopen", id)
	}
}

// TestAllowExploitMigratesFromPreExploitSchema simulates a database created
// before the allow_exploit column existed (but after allow_code_exec), the
// same way the legacy-profile test simulates a pre-code-exec schema.
func TestAllowExploitMigratesFromPreExploitSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "projects.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateProject(ctx, "legacy-project")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("ALTER TABLE projects DROP COLUMN allow_exploit"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopening a pre-allow_exploit database must migrate, not fail: %v", err)
	}
	defer s.Close()
	projects, err := s.ListProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range projects {
		if x.ID == id {
			found = true
			if x.AllowExploit {
				t.Fatalf("migrated column must default allow_exploit to false")
			}
		}
	}
	if !found {
		t.Fatalf("project %d not found after migration", id)
	}
}

func TestAllowCredentialAttackRoundTripAndMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "projects.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateProject(ctx, "credential-attack-project")
	if err != nil {
		t.Fatal(err)
	}
	projects, err := s.ListProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var p domain.Project
	for _, x := range projects {
		if x.ID == id {
			p = x
		}
	}
	if p.AllowCredentialAttack {
		t.Fatalf("new project must default allow_credential_attack to false")
	}
	if p.LockoutMaxAttempts != 0 || p.LockoutWindowMinutes != 0 {
		t.Fatalf("new project must default lockout settings to 0 (\"use the conservative default\"), got %d/%d", p.LockoutMaxAttempts, p.LockoutWindowMinutes)
	}
	p.AllowCredentialAttack = true
	p.LockoutMaxAttempts = 5
	p.LockoutWindowMinutes = 45
	if err := s.SetProjectScanSettings(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening must also work against a database created before these
	// columns existed — same "add column" migration path as allow_code_exec.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	projects, err = s.ListProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range projects {
		if x.ID == id {
			found = true
			if !x.AllowCredentialAttack {
				t.Fatalf("allow_credential_attack did not round-trip: got false, want true")
			}
			if x.LockoutMaxAttempts != 5 || x.LockoutWindowMinutes != 45 {
				t.Fatalf("lockout settings did not round-trip: got %d/%d, want 5/45", x.LockoutMaxAttempts, x.LockoutWindowMinutes)
			}
		}
	}
	if !found {
		t.Fatalf("project %d not found after reopen", id)
	}
}

// TestAllowCredentialAttackMigratesFromPreCredentialSchema simulates a
// database created before these columns existed, the same way
// TestAllowExploitMigratesFromPreExploitSchema simulates a pre-allow_exploit
// schema.
func TestAllowCredentialAttackMigratesFromPreCredentialSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "projects.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateProject(ctx, "legacy-project")
	if err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"allow_credential_attack", "lockout_max_attempts", "lockout_window_minutes"} {
		if _, err := s.db.Exec("ALTER TABLE projects DROP COLUMN " + col); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopening a pre-credential-attack database must migrate, not fail: %v", err)
	}
	defer s.Close()
	projects, err := s.ListProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range projects {
		if x.ID == id {
			found = true
			if x.AllowCredentialAttack || x.LockoutMaxAttempts != 0 || x.LockoutWindowMinutes != 0 {
				t.Fatalf("migrated columns must default to false/0/0, got %v/%d/%d", x.AllowCredentialAttack, x.LockoutMaxAttempts, x.LockoutWindowMinutes)
			}
		}
	}
	if !found {
		t.Fatalf("project %d not found after migration", id)
	}
}
