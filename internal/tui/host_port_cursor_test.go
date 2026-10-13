package tui

import (
	"strings"
	"testing"
	"wscan/internal/domain"

	"github.com/charmbracelet/x/ansi"
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
	if m.serviceIndex != 0 || !m.selectedPortMissing() || m.preferredPort != 445 {
		t.Fatal("missing port did not select the nearest port while preserving the preference")
	}
	ports := ansi.Strip(m.renderServicesColumn(70, 20))
	if !strings.Contains(ports, "445/tcp — нет") || strings.Count(ports, "▶") != 1 {
		t.Fatal("missing port should be a notice, with only the actual port selected")
	}
	if strings.Contains(ansi.Strip(m.renderDetailsColumn(70, 20)), "445/tcp") {
		t.Fatal("results repeat the missing-port notice")
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

func TestNearestPortCursorKeepsPreferenceUntilPortIsChanged(t *testing.T) {
	m := model{screen: "desk", hostIndex: 0, serviceIndex: 0, hostOrder: []string{"a", "b", "empty", "c"}, inventory: map[string]*hostInfo{
		"a":     {services: []domain.Service{{Host: "a", Port: 22, Protocol: "tcp"}}},
		"b":     {services: []domain.Service{{Host: "b", Port: 21, Protocol: "udp"}, {Host: "b", Port: 23, Protocol: "tcp"}, {Host: "b", Port: 80, Protocol: "tcp"}}, findings: []domain.Finding{{Target: "b", MatchedAt: "tcp://b:23", Protocol: "tcp", TemplateID: "nearest-result"}}},
		"empty": {},
		"c":     {services: []domain.Service{{Host: "c", Port: 22, Protocol: "tcp"}, {Host: "c", Port: 80, Protocol: "tcp"}}},
	}}
	next, _ := m.updateDesk("down")
	m = next.(model)
	if m.serviceIndex != 1 || m.preferredPort != 22 || len(m.deskFindings()) != 1 {
		t.Fatal("nearest port should break ties by protocol and show its results")
	}
	for i := 0; i < 2; i++ {
		next, _ = m.updateDesk("down")
		m = next.(model)
		if m.preferredPort != 22 {
			t.Fatal("browsing hosts overwrote the preferred port")
		}
		if i == 0 && (m.serviceIndex != -1 || !m.selectedPortMissing()) {
			t.Fatal("empty host should preserve the preference without a selected port")
		}
	}
	if m.serviceIndex != 0 || m.selectedPortMissing() {
		t.Fatal("the original port should be restored after missing and empty hosts")
	}
	next, _ = m.updateDesk("up")
	m = next.(model)
	next, _ = m.updateDesk("up")
	m = next.(model)
	m.focusCol = 1
	next, _ = m.updateDesk("down")
	m = next.(model)
	if m.preferredPort != 80 || m.selectedPortMissing() {
		t.Fatal("explicitly changing the port should replace the preference")
	}
	m.focusCol = 0
	for i := 0; i < 2; i++ {
		next, _ = m.updateDesk("down")
		m = next.(model)
	}
	if m.preferredPort != 80 || m.serviceIndex != 1 {
		t.Fatal("new explicit port selection was not preserved")
	}
}
