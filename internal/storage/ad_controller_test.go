package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestADControllerSelectionPersistsAndIsProjectScoped(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.CreateProject(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateProject(ctx, "b")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetADController(ctx, a, "192.0.2.10", "a.example"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetADController(ctx, b, "dc.b.example", "b.example"); err != nil {
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
	for _, tc := range []struct {
		id          int64
		host, realm string
	}{{a, "192.0.2.10", "a.example"}, {b, "dc.b.example", "b.example"}} {
		host, realm, err := s.ADController(ctx, tc.id)
		if err != nil || host != tc.host || realm != tc.realm {
			t.Fatalf("lost selection: %s %s %v", host, realm, err)
		}
	}
	if err := s.SetADController(ctx, a, "", ""); err != nil {
		t.Fatal(err)
	}
	if host, _, err := s.ADController(ctx, a); err != nil || host != "" {
		t.Fatal("automatic mode not restored")
	}
	if host, _, err := s.ADController(ctx, b); err != nil || host != "dc.b.example" {
		t.Fatal("clearing A changed B")
	}
	if err := s.DeleteProject(ctx, b); err != nil {
		t.Fatal(err)
	}
	if host, _, err := s.ADController(ctx, b); err != nil || host != "" {
		t.Fatal("deleted project retained controller")
	}
	if err := s.SetADController(ctx, 9999, "192.0.2.1", ""); err == nil {
		t.Fatal("orphan selection accepted")
	}
}
