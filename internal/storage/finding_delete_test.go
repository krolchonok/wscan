package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
	"wscan/internal/domain"
)

func TestDeleteFindingsProjectHistoryAndNewResults(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "results.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.CreateProject(ctx, "one")
	if e != nil {
		t.Fatal(e)
	}
	other, e := s.CreateProject(ctx, "two")
	if e != nil {
		t.Fatal(e)
	}
	r1, _ := s.StartRun(ctx, p)
	r2, _ := s.StartRun(ctx, p)
	r3, _ := s.StartRun(ctx, other)
	f := domain.Finding{Target: "10.0.0.10", TemplateID: "check", MatchedAt: "tcp://10.0.0.10:445", Time: time.Now()}
	old := f
	old.Time = f.Time.Add(-time.Hour)
	newer := f
	newer.Time = f.Time.Add(time.Second)
	keep := f
	keep.TemplateID = "other-check"
	for _, item := range []struct {
		run int64
		f   domain.Finding
	}{{r1, old}, {r2, f}, {r2, newer}, {r2, keep}, {r3, f}} {
		if e = s.SaveFinding(ctx, item.run, item.f); e != nil {
			t.Fatal(e)
		}
	}
	n, e := s.DeleteFindings(ctx, p, []domain.Finding{f})
	if e != nil || n != 2 {
		t.Fatalf("delete=%d %v", n, e)
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	first, _ := s.Findings(ctx, r1)
	second, _ := s.Findings(ctx, r2)
	third, _ := s.Findings(ctx, r3)
	if len(first) != 0 || len(second) != 2 || len(third) != 1 {
		t.Fatalf("history/project isolation: %d %d %d", len(first), len(second), len(third))
	}
	if !second[0].Time.Equal(newer.Time) {
		t.Fatal("new result deleted after confirmation snapshot")
	}
}
