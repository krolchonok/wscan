package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestExplicitPTRNamesSurviveCacheExpiryAndAutomaticLookup(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "ptr.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	id, err := s.CreateProject(ctx, "ptr")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SavePTRHostNames(ctx, id, map[string][]string{"192.0.2.1": {"host.lab"}}, "192.0.2.53:53"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE host_names SET queried_at='2000-01-01T00:00:00Z'"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveHostNames(ctx, id, map[string][]string{"192.0.2.1": nil}); err != nil {
		t.Fatal(err)
	}
	names, err := s.HostNames(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := names["192.0.2.1"]; len(got.Names) != 1 || got.Names[0] != "host.lab" || got.Server != "192.0.2.53:53" {
		t.Fatalf("lost explicit name: %+v", got)
	}
}
