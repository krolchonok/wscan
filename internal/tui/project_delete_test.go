package tui

import (
	"context"
	"path/filepath"
	"testing"
	"wscan/internal/storage"
)

func TestProjectDeleteConfirmCancelAndActiveJobs(t *testing.T) {
	s, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	id, err := s.CreateProject(ctx, "remove")
	if err != nil {
		t.Fatal(err)
	}
	m := model{ctx: ctx, store: s, screen: "projects"}
	if err := m.reload(); err != nil {
		t.Fatal(err)
	}
	m.current = m.projects[0]
	m.requestProjectDelete()
	if m.screen != "project-delete-confirm" {
		t.Fatal("missing confirmation")
	}
	updated, _ := m.updateProjectDelete("esc")
	m = updated.(model)
	if len(m.projects) != 1 || m.screen != "projects" {
		t.Fatal("cancel changed project")
	}
	m.jobs = []*job{{projectID: id, status: statusRunning}}
	m.requestProjectDelete()
	if m.screen != "projects" {
		t.Fatal("active project can be deleted")
	}
	m.jobs[0].status = statusDone
	m.requestProjectDelete()
	updated, _ = m.updateProjectDelete("enter")
	m = updated.(model)
	if len(m.projects) != 0 || len(m.jobs) != 0 || m.current.ID != 0 || m.screen != "projects" {
		t.Fatalf("state after deletion: projects=%v current=%v screen=%s", m.projects, m.current, m.screen)
	}
}
