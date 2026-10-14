package tui

import (
	"context"
	"strings"
	"testing"
	"wscan/internal/domain"
)

func TestKerberoastRequiresSelectedCredential(t *testing.T) {
	m := model{ctx: context.Background(), current: domain.Project{ID: 1}, adAccessHost: "127.0.0.1", adAccessDomain: "lab.local", adAccessCred: -1}
	for i, row := range adAccessModes {
		if row.id == "kerberoast" {
			m.adAccessIndex = i
		}
	}
	result, command := m.startADAccess()
	got := result.(model)
	if command != nil || !strings.Contains(got.message, "учётку") {
		t.Fatal(got.message)
	}
	_, command = m.updateADAccess("s")
	if command != nil {
		t.Fatal("SPN input started a network job")
	}
}
