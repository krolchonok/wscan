package tui

import (
	"strings"
	"testing"
	"wscan/internal/domain"
)

func TestHostNavigationKeepsSelectedPortAcrossMissingHosts(t *testing.T) {
	m := model{screen: "desk", width: 160, height: 40, hostIndex: 0, serviceIndex: 1, hostOrder: []string{"a", "b", "c", "d"}, inventory: map[string]*hostInfo{
		"a": {services: []domain.Service{{Host: "a", Port: 80, Protocol: "tcp"}, {Host: "a", Port: 445, Protocol: "tcp"}}},
		"b": {services: []domain.Service{{Host: "b", Port: 445, Protocol: "udp"}, {Host: "b", Port: 22, Protocol: "tcp"}, {Host: "b", Port: 445, Protocol: "tcp"}}},
		"c": {services: []domain.Service{{Host: "c", Port: 80, Protocol: "tcp"}}},
		"d": {services: []domain.Service{{Host: "d", Port: 445, Protocol: "tcp"}}},
	}}
	next, _ := m.updateDesk("down")
	m = next.(model)
	if m.serviceIndex != 2 {
		t.Fatalf("selected wrong protocol/row: %d", m.serviceIndex)
	}
	next, _ = m.updateDesk("down")
	m = next.(model)
	if m.serviceIndex != -1 || !m.selectedPortMissing() || len(m.deskFindings()) != 0 {
		t.Fatal("missing port fell back to unrelated port results")
	}
	if !strings.Contains(m.renderDetailsColumn(70, 20), "445/tcp не найден") {
		t.Fatal("missing port not explained")
	}
	next, _ = m.updateDesk("down")
	m = next.(model)
	if m.serviceIndex != 0 || m.selectedPortMissing() {
		t.Fatal("selection not restored after missing host")
	}
	next, _ = m.updateDesk("up")
	m = next.(model)
	next, _ = m.updateDesk("up")
	m = next.(model)
	if m.serviceIndex != 2 {
		t.Fatal("reverse navigation lost selected port")
	}
	// Explicitly selecting 'all ports' clears the saved port.
	m.focusCol = 1
	m.serviceIndex = 0
	next, _ = m.updateDesk("up")
	m = next.(model)
	m.focusCol = 0
	next, _ = m.updateDesk("up")
	m = next.(model)
	if m.serviceIndex != -1 || m.preferredPort != 0 {
		t.Fatal("all ports selection was not preserved")
	}
}
