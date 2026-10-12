package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"wscan/internal/engine"
	"wscan/internal/storage"
)

func waitJob(t *testing.T, m *Manager, id int) Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, ok := m.Get(id)
		if ok && j.Status != "running" && j.Status != "cancelling" {
			return j
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("job did not finish")
	return Job{}
}
func TestManagerCompletionCancellationAndIdempotency(t *testing.T) {
	m, err := NewManager(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var executions atomic.Int32
	req := JobRequest{ProjectID: 1, Kind: "fixture", Label: "fixture", Targets: []string{"127.0.0.1"}, Source: "tui"}
	j, err := m.Start(req, "same", func(ctx context.Context, emit Reporter) (Outcome, error) {
		executions.Add(1)
		emit("Проверка", 1, 2)
		return Outcome{Result: engine.Result{RunID: 42}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := m.Start(req, "same", func(context.Context, Reporter) (Outcome, error) {
		t.Error("duplicate execution")
		return Outcome{}, nil
	})
	if err != nil || repeated.ID != j.ID {
		t.Fatalf("deduplication: %+v %v", repeated, err)
	}
	completed := waitJob(t, m, j.ID)
	if completed.Status != "done" || completed.RunID != 42 || executions.Load() != 1 {
		t.Fatalf("successful execution marked cancelled: %+v", completed)
	}
	req.Label = "different"
	if _, err := m.Start(req, "same", func(context.Context, Reporter) (Outcome, error) { return Outcome{}, nil }); err == nil {
		t.Fatal("key reused with different request")
	}
	running, err := m.Start(req, "", func(ctx context.Context, emit Reporter) (Outcome, error) {
		emit("Ожидание")
		<-ctx.Done()
		return Outcome{}, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Cancel(running.ID); err != nil {
		t.Fatal(err)
	}
	if j := waitJob(t, m, running.ID); j.Status != "cancelled" {
		t.Fatalf("cancel: %+v", j)
	}
}
func TestManagerRestoresHistoryAndMarksInterrupted(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	raw, _ := json.Marshal(Job{ID: 10, Key: "persisted", JobRequest: JobRequest{Label: "old", Fingerprint: "old", ProjectID: 3}, Status: "running", Started: time.Now()})
	if err := store.SaveJob(context.Background(), 10, raw); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if j, ok := m.Get(10); !ok || j.Status != "interrupted" {
		t.Fatalf("history: %+v", j)
	}
	req := JobRequest{Label: "completed", ProjectID: 3, Fingerprint: "new"}
	j, err := m.Start(req, "next", func(context.Context, Reporter) (Outcome, error) { return Outcome{ProjectID: 3}, nil })
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, m, j.ID)
	m.Close()
	restored, err := NewManager(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if j2, ok := restored.Get(j.ID); !ok || j2.Status != "done" {
		t.Fatalf("terminal state lost: %+v", j2)
	}
	repeated, err := restored.Start(req, "next", func(context.Context, Reporter) (Outcome, error) {
		t.Error("restart repeated completed job")
		return Outcome{}, nil
	})
	if err != nil || repeated.ID != j.ID {
		t.Fatalf("restart dedup: %v %+v", err, repeated)
	}
}
