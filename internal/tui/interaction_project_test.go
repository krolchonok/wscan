package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"strings"
	"testing"
	"wscan/internal/domain"
)

func TestProjectInteractionMenuAvailableWithoutHosts(t *testing.T) {
	m := model{screen: "networks", current: domain.Project{ID: 1, Name: "lab"}}
	got, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("4")})
	m = got.(model)
	if cmd != nil || m.screen != "interaction-menu" || !strings.Contains(m.navigationLine(), "4 Взаимодействие") {
		t.Fatal("project menu missing")
	}
	m.interactionIndex = 7
	got, cmd = m.updateInteractionMenu("enter")
	m = got.(model)
	if cmd != nil || m.screen != "web-discovery" {
		t.Fatal("manual URL setup not available without hosts")
	}
	got, _ = m.updateWebDiscovery("esc")
	m = got.(model)
	got, _ = m.updateInteractionMenu("esc")
	if got.(model).screen != "networks" {
		t.Fatal("menu lost return screen")
	}
}
func TestProjectInteractionHostSelection(t *testing.T) {
	m := workspaceFixture()
	m.screen = "networks"
	m.openProjectInteractions()
	got, _ := m.updateInteractionMenu("h")
	m = got.(model)
	hosts := m.interactionHosts()
	if m.screen != "interaction-targets" || len(hosts) < 2 {
		t.Fatal("host picker missing")
	}
	m.interactionHostIndex = 1
	got, _ = m.updateInteractionTargets("enter")
	m = got.(model)
	if m.screen != "interaction-menu" || m.currentHost() != hosts[1] || m.smbBrowser.host != hosts[1] || m.interactionReturn != "networks" {
		t.Fatalf("target not selected: %s %s", m.currentHost(), m.smbBrowser.host)
	}
}
func TestWebInteractionSelectedPort(t *testing.T) {
	service := domain.Service{Host: "127.0.0.1", Port: 8087, Name: "http", Protocol: "tcp"}
	m := model{screen: "desk", hostOrder: []string{service.Host}, inventory: map[string]*hostInfo{service.Host: {services: []domain.Service{service}}}, focusCol: 1}
	m.openInteractionMenu()
	if m.interactionIndex != 7 {
		t.Fatal("Web tool not focused")
	}
	got, cmd := m.updateInteractionMenu("enter")
	m = got.(model)
	if cmd != nil || m.webDiscovery.options.URL != "http://127.0.0.1:8087" && m.webDiscovery.options.URL != "http://127.0.0.1:8087/" {
		t.Fatalf("target %q", m.webDiscovery.options.URL)
	}
}
