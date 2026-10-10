package tui

import (
	"context"
	"path/filepath"
	"testing"

	"wscan/internal/storage"
)

func newTestModelForSettings(t *testing.T) model {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()
	id, err := store.CreateProject(ctx, "code-exec-test")
	if err != nil {
		t.Fatal(err)
	}
	projects, err := store.ListProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var m model
	m.store = store
	m.ctx = ctx
	m.projects = projects
	for _, p := range projects {
		if p.ID == id {
			m.current = p
		}
	}
	m.screen = "settings"
	m.settingsIndex = 11
	return m
}

// Enabling AllowCodeExec must route through a confirmation screen, not flip
// immediately — code: shells out to a real external interpreter on the
// scanner's own machine, the one request type outside the native engine.
func TestAllowCodeExecRequiresConfirmation(t *testing.T) {
	m := newTestModelForSettings(t)
	if m.current.AllowCodeExec {
		t.Fatal("new project must default to AllowCodeExec=false")
	}

	got, _ := m.updateSettings("enter")
	m2 := got.(model)
	if m2.screen != "code-exec-confirm" {
		t.Fatalf("enabling must open the confirm screen, got screen=%q", m2.screen)
	}
	if m2.current.AllowCodeExec {
		t.Fatal("must not be enabled yet — only after confirming")
	}

	// Esc cancels: nothing persisted.
	cancelled, _ := m2.updateCodeExecConfirm("esc")
	m3 := cancelled.(model)
	if m3.screen != "settings" || m3.current.AllowCodeExec {
		t.Fatalf("esc must cancel back to settings with AllowCodeExec still false, got screen=%q allow=%v", m3.screen, m3.current.AllowCodeExec)
	}

	// Enter confirms: now it's actually enabled and persisted.
	confirmed, _ := m2.updateCodeExecConfirm("enter")
	m4 := confirmed.(model)
	if m4.screen != "settings" || !m4.current.AllowCodeExec {
		t.Fatalf("enter must confirm and enable, got screen=%q allow=%v", m4.screen, m4.current.AllowCodeExec)
	}
	reloaded, err := m4.store.ListProjects(m4.ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range reloaded {
		if p.ID == m4.current.ID {
			found = true
			if !p.AllowCodeExec {
				t.Fatal("AllowCodeExec was not persisted to storage")
			}
		}
	}
	if !found {
		t.Fatal("project not found after confirm")
	}
}

// Disabling must NOT require confirmation — only turning it on is risky.
func TestAllowCodeExecDisableNeedsNoConfirmation(t *testing.T) {
	m := newTestModelForSettings(t)
	m.current.AllowCodeExec = true

	got, _ := m.updateSettings("enter")
	m2 := got.(model)
	if m2.screen == "code-exec-confirm" {
		t.Fatal("disabling must not open the confirm screen")
	}
	if m2.current.AllowCodeExec {
		t.Fatal("disabling must take effect immediately")
	}
}
