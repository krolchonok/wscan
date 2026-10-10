package tui

import (
	"reflect"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

func TestHostSelectionFilters(t *testing.T) {
	m := model{
		current:   domain.Project{ID: 1},
		hostOrder: []string{"tcp", "udp", "closed", "ping", "unknown"},
		inventory: map[string]*hostInfo{
			"tcp":     {services: []domain.Service{{Port: 53, Protocol: "tcp", State: "open"}}},
			"udp":     {services: []domain.Service{{Port: 53, Protocol: "udp"}}},
			"closed":  {services: []domain.Service{{Port: 53, Protocol: "tcp", State: "closed"}}},
			"outside": {services: []domain.Service{{Port: 53}}},
		},
		jobs: []*job{
			{projectID: 1, kind: jobAlive, result: &engine.Result{LiveHosts: []string{"ping"}}},
			{projectID: 2, kind: jobAlive, result: &engine.Result{LiveHosts: []string{"unknown"}}},
			{projectID: 1, kind: jobPTR, result: &engine.Result{LiveHosts: []string{"unknown"}}},
			{projectID: 1, kind: jobAlive},
		},
	}
	for _, tc := range []struct {
		mode, protocol string
		port           int
		want           []string
	}{
		{"all", "", 0, m.hostOrder},
		{"alive", "", 0, []string{"tcp", "udp", "ping"}},
		{"port", "tcp", 53, []string{"tcp"}},
		{"port", "udp", 53, []string{"udp"}},
	} {
		m.selectMatchingHosts(tc.mode, tc.port, tc.protocol)
		if got := m.selectedTargetHosts(); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s/%s: got %v, want %v", tc.mode, tc.protocol, got, tc.want)
		}
		m.openActionMenu(nil)
		if !reflect.DeepEqual(m.actionHosts, tc.want) {
			t.Fatalf("action hosts: %v", m.actionHosts)
		}
	}
	m.selectMatchingHosts("port", 9999, "tcp")
	if !reflect.DeepEqual(m.selectedTargetHosts(), []string{"udp"}) {
		t.Fatal("empty match changed selection")
	}
}

func TestHostSelectionPortInput(t *testing.T) {
	m := model{screen: "desk"}
	updated, _ := m.updateDesk("f")
	m = updated.(model)
	m.actionIndex = 2
	updated, _ = m.updateHostSelection("enter")
	m = updated.(model)
	updated, _ = m.updateHostPortSelection("enter")
	m = updated.(model)
	if m.screen != "input" || m.inputAction != "select-host-port" {
		t.Fatal("port input did not open")
	}
	m.input = "65536"
	updated, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if m.screen != "input" || m.message == "" {
		t.Fatal("invalid port did not retain input")
	}
}

func TestHostPortChoicesAndInteractiveSelection(t *testing.T) {
	m := model{screen: "host-port-selection", hostOrder: []string{"one", "two", "closed"}, inventory: map[string]*hostInfo{
		"one":     {services: []domain.Service{{Port: 443}, {Port: 53, Protocol: "udp"}, {Port: 443, Protocol: "tcp"}}},
		"two":     {services: []domain.Service{{Port: 443, Protocol: "tcp", State: "open"}, {Port: 53, Protocol: "tcp"}}},
		"closed":  {services: []domain.Service{{Port: 22, State: "closed"}}},
		"outside": {services: []domain.Service{{Port: 80}}},
	}}
	want := []hostPortChoice{{53, "tcp", 1}, {53, "udp", 1}, {443, "tcp", 2}}
	if got := m.hostPortChoices(); !reflect.DeepEqual(got, want) {
		t.Fatalf("choices: %v, want %v", got, want)
	}
	updated, _ := m.updateHostPortSelection("down")
	m = updated.(model)
	updated, _ = m.updateHostPortSelection("enter")
	m = updated.(model)
	if m.screen != "desk" || !reflect.DeepEqual(m.selectedTargetHosts(), []string{"one"}) {
		t.Fatalf("selection: %s %v", m.screen, m.selectedTargetHosts())
	}
	m.screen, m.actionIndex = "host-port-selection", 2
	updated, _ = m.updateHostPortSelection("enter")
	m = updated.(model)
	if !reflect.DeepEqual(m.selectedTargetHosts(), []string{"one", "two"}) {
		t.Fatalf("TCP selection: %v", m.selectedTargetHosts())
	}
	updated, _ = m.updateHostPortSelection("esc")
	m = updated.(model)
	if m.screen != "host-selection" || m.actionIndex != 2 {
		t.Fatal("back navigation failed")
	}
}
