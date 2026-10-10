package tui

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wscan/internal/domain"
	"wscan/internal/storage"
)

// TestLoadInventoryNewestRunWinsOnConflict reproduces a real bug: the active
// SMB probe added in internal/discovery/smb_identify.go lets a rescan
// correctly identify a port (e.g. Name/Product/Version) that an earlier run
// left blank or wrong. storage.Runs returns history newest-first (id DESC),
// and mergeService lets any non-empty field unconditionally win — so
// replaying that history in storage order let the OLDER, stale run's
// non-empty fields clobber the newer, correct ones every time the project
// was reopened (loadInventory). The fix replays oldest-to-newest so the most
// recent scan's identification always survives.
func TestLoadInventoryNewestRunWinsOnConflict(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_ = os.MkdirAll(dir, 0700)

	ctx := context.Background()
	projectID, err := store.CreateProject(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}

	oldRunID, err := store.StartRun(ctx, projectID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveService(ctx, oldRunID, domain.Service{
		Host: "10.0.0.133", Port: 4445, Protocol: "tcp", Name: "unknown", Target: "10.0.0.133",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRun(ctx, oldRunID, "done"); err != nil {
		t.Fatal(err)
	}

	newRunID, err := store.StartRun(ctx, projectID)
	if err != nil {
		t.Fatal(err)
	}
	if newRunID <= oldRunID {
		t.Fatalf("expected the second run to have a higher id (oldRunID=%d, newRunID=%d)", oldRunID, newRunID)
	}
	if err := store.SaveService(ctx, newRunID, domain.Service{
		Host: "10.0.0.133", Port: 4445, Protocol: "tcp", Name: "microsoft-ds",
		Product: "Windows", Version: "Windows 7 SP1 / Server 2008 R2 (build 7601)", Target: "10.0.0.133",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRun(ctx, newRunID, "done"); err != nil {
		t.Fatal(err)
	}

	history, err := store.Runs(ctx, projectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].ID != newRunID {
		t.Fatalf("expected storage.Runs to return newest-first, got %+v", history)
	}

	m := &model{ctx: ctx, store: store, current: domain.Project{ID: projectID}, history: history}
	m.loadInventory()

	services := m.servicesFor("10.0.0.133")
	if len(services) != 1 {
		t.Fatalf("expected one merged service, got %+v", services)
	}
	s := services[0]
	if s.Name != "microsoft-ds" || s.Product != "Windows" || s.Version != "Windows 7 SP1 / Server 2008 R2 (build 7601)" {
		t.Fatalf("newest run's identification was clobbered by the older run: %+v", s)
	}
	_ = time.Now()
}
