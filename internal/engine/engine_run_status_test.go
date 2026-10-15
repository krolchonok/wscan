package engine

import (
	"context"
	"errors"
	"testing"

	"wscan/internal/domain"
)

func TestScanMarksEarlyStorageFailureAsFailed(t *testing.T) {
	store := &fakeStore{saveServiceErr: errors.New("save service failed")}
	e := New(store, Config{})
	_, err := e.Scan(context.Background(), domain.Project{
		ID:       1,
		Targets:  []string{"127.0.0.1"},
		Services: []domain.Service{{Host: "127.0.0.1", Port: 80, Protocol: "tcp"}},
	}, nil)
	if err == nil {
		t.Fatal("expected storage failure")
	}
	if len(store.finishStatuses) != 1 || store.finishStatuses[0] != "failed" {
		t.Fatalf("finish statuses=%v, want [failed]", store.finishStatuses)
	}
}

func TestScanFinishesSuccessfulRunOnce(t *testing.T) {
	store := &fakeStore{}
	e := New(store, Config{})
	if _, err := e.Scan(context.Background(), domain.Project{ID: 1}, nil); err != nil {
		t.Fatal(err)
	}
	if len(store.finishStatuses) != 1 || store.finishStatuses[0] != "completed" {
		t.Fatalf("finish statuses=%v, want [completed]", store.finishStatuses)
	}
}
