package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDeleteProjectRemovesRelatedDataOnly(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, name := range []string{"remove", "keep"} {
		id, err := s.CreateProject(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		run, err := s.StartRun(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		for _, query := range []string{
			`INSERT INTO targets VALUES(?, 'example.test')`,
			`INSERT INTO project_templates VALUES(?, 'check')`,
			`INSERT INTO host_names(project_id,host,names,queried_at) VALUES(?, 'example.test', '[]', '')`,
			`INSERT INTO inventory_exclusions VALUES(?, 'example.test', '')`,
			`INSERT INTO inventory_resets VALUES(?, 'example.test', 0, '[]')`,
			`INSERT INTO credentials(project_id,type,username,secret) VALUES(?, 'password', 'user', 'secret')`,
			`INSERT INTO credential_attempts(project_id,target,username,protocol,success,attempted_at) VALUES(?, 'example.test', 'user', 'ssh', 0, '')`,
		} {
			if _, err := s.db.ExecContext(ctx, query, id); err != nil {
				t.Fatal(err)
			}
		}
		for _, table := range []string{"services", "findings"} {
			if _, err := s.db.ExecContext(ctx, "INSERT INTO "+table+"(run_id,data) VALUES(?, '{}')", run); err != nil {
				t.Fatal(err)
			}
		}
	}
	projects, err := s.ListProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var removeID int64
	for _, p := range projects {
		if p.Name == "remove" {
			removeID = p.ID
		}
	}
	if err := s.DeleteProject(ctx, removeID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"projects", "targets", "project_templates", "runs", "services", "findings", "host_names", "inventory_exclusions", "inventory_resets", "credentials", "credential_attempts"} {
		var count int
		if err := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s: count=%d err=%v", table, count, err)
		}
	}
	projects, err = s.ListProjects(ctx)
	if err != nil || len(projects) != 1 || projects[0].Name != "keep" {
		t.Fatalf("remaining projects: %v %v", projects, err)
	}
}
