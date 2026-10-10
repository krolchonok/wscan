package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNetworkPTRMenuRequestsServer(t *testing.T) {
	m := model{screen: "action-menu", actionHosts: []string{"192.0.2.0/24"}, actionReturn: "networks"}
	index := -1
	for i, row := range m.actionRows() {
		if row.kind == jobPTR {
			index = i
		}
	}
	if index < 0 {
		t.Fatal("PTR action absent")
	}
	m.actionIndex = index
	next, _ := m.updateActionMenu("enter")
	m = next.(model)
	if m.screen != "input" || m.inputAction != "ptr-server" {
		t.Fatalf("wrong input: %s %s", m.screen, m.inputAction)
	}
	if !strings.Contains(m.viewInput(100), "DNS") {
		t.Fatal("missing server prompt")
	}
	m.input = "invalid"
	next, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if len(m.jobs) != 0 || m.message == "" {
		t.Fatal("invalid server launched")
	}
}
