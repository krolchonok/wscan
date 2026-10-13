package tui

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
)

func workspaceFixture() model {
	m := model{
		screen: "desk", width: 128, height: 30,
		current: domain.Project{ID: 1, Name: "AD lab", Targets: []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.0.10", "10.0.1.20", "dc.example.test"}},
		inventory: map[string]*hostInfo{
			"10.0.0.10":       {services: []domain.Service{{Host: "10.0.0.10", Port: 445, Name: "smb", Protocol: "tcp", Product: "Microsoft Windows Server", Version: "long version metadata for checking narrow panes"}}},
			"10.0.1.20":       {services: []domain.Service{{Host: "10.0.1.20", Port: 5985, Name: "winrm", Protocol: "tcp"}}},
			"dc.example.test": {services: []domain.Service{{Host: "10.0.0.11", Port: 389, Name: "ldap", Protocol: "tcp"}}},
			"10.0.0.12":       {},
		},
	}
	m.rebuildHostOrder()
	return m
}

func TestWorkspacePanesFitTerminalBeforeCropping(t *testing.T) {
	for _, width := range []int{48, 80, 88, 100, 127, 128, 160, 240} {
		for _, height := range []int{18, 24, 40} {
			for _, screen := range []string{"desk", "networks"} {
				for focus := 0; focus < 3; focus++ {
					t.Run(fmt.Sprintf("%s-%dx%d-focus%d", screen, width, height, focus), func(t *testing.T) {
						m := workspaceFixture()
						m.width, m.height, m.screen, m.focusCol = width, height, screen, focus
						body := m.viewDesk(width)
						if screen == "networks" {
							body = m.viewNetworks(width)
						}
						if lipgloss.Width(body) != width || lipgloss.Height(body) != m.bodyHeight() {
							t.Fatalf("uncropped pane is %dx%d, want %dx%d", lipgloss.Width(body), lipgloss.Height(body), width, m.bodyHeight())
						}
						view := m.View()
						if lipgloss.Height(view) != height {
							t.Fatalf("view height %d", lipgloss.Height(view))
						}
						for _, line := range strings.Split(view, "\n") {
							if ansi.StringWidth(line) != width {
								t.Fatalf("line width %d", ansi.StringWidth(line))
							}
						}
					})
				}
			}
		}
	}
}

func TestSubnetHostScopeRestrictsActionsAndKeepsDomains(t *testing.T) {
	m := workspaceFixture()
	m.openHostScope("10.0.0.0/24")
	want := []string{"10.0.0.10", "10.0.0.12", "dc.example.test"}
	if !reflect.DeepEqual(m.hostOrder, want) {
		t.Fatalf("scope %v, want %v", m.hostOrder, want)
	}
	if m.networkHostCount("10.0.1.0/24") != 1 {
		t.Fatal("count depends on currently visible subnet")
	}
	m.hostIndex = -1
	m.openActionMenu(nil)
	if !reflect.DeepEqual(m.actionHosts, want) {
		t.Fatalf("all-host action escaped scope: %v", m.actionHosts)
	}
	m.screen = "networks"
	m.selectedHosts = map[string]bool{"10.0.1.20": true}
	next, _ := m.updateNetworks(" ")
	m = next.(model)
	if !m.selectedNetworks["10.0.0.0/24"] || !m.selectedHosts["10.0.1.20"] {
		t.Fatal("subnet selection overwrote host selection")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	m = next.(model)
	if m.screen != "desk" || m.hostNetwork != "" || len(m.hostOrder) != 4 {
		t.Fatal("navigation did not restore all hosts")
	}
}

func TestHostOrderSortsIPv4Numerically(t *testing.T) {
	m := model{
		current:   domain.Project{Targets: []string{"192.0.2.151", "192.0.2.16"}},
		inventory: map[string]*hostInfo{},
	}
	m.rebuildHostOrder()
	want := []string{"192.0.2.16", "192.0.2.151"}
	if !reflect.DeepEqual(m.hostOrder, want) {
		t.Fatalf("host order %v, want %v", m.hostOrder, want)
	}
}

func TestCompactHostViewShowsFocusedPane(t *testing.T) {
	m := workspaceFixture()
	m.width = 80
	for focus, title := range []string{"ХОСТЫ", "ПОРТЫ", "РЕЗУЛЬТАТЫ"} {
		m.focusCol = focus
		if !strings.Contains(ansi.Strip(m.viewDesk(80)), title) {
			t.Fatalf("focused %s pane is hidden", title)
		}
	}
}

func TestDiscoveryDialogKeepsPnVisibleAndSpaceToggles(t *testing.T) {
	m := workspaceFixture()
	m.screen, m.width, m.height, m.discOptIndex = "disc-options", 160, 18, 9
	if !strings.Contains(ansi.Strip(m.viewDiscOptions(160)), "-Pn") {
		t.Fatalf("selected -Pn option is cropped:\n%s", ansi.Strip(m.viewDiscOptions(160)))
	}
	next, _ := m.updateDiscOptions("space")
	m = next.(model)
	if !m.discNoPing || m.screen != "disc-options" || len(m.jobs) != 0 {
		t.Fatal("Space launched a scan instead of toggling -Pn")
	}
}

func TestSubnetJobResultOpensItsHostScope(t *testing.T) {
	m := workspaceFixture()
	m.jobs = []*job{{id: 1, projectID: 1, targets: []string{"10.0.1.0/24"}, status: statusDone}}
	next, _ := m.updateJobDetails("enter")
	m = next.(model)
	if m.screen != "desk" || m.hostNetwork != "10.0.1.0/24" || !reflect.DeepEqual(m.hostOrder, []string{"10.0.1.20"}) {
		t.Fatalf("result opened wrong inventory: %s %s %v", m.screen, m.hostNetwork, m.hostOrder)
	}
}

func TestMainHostsUsesDiscoveryResultsWorkspace(t *testing.T) {
	m := workspaceFixture()
	m.sidebarEnabled = true
	m.width = 180
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	main := next.(model)
	if main.screen != "desk" || main.hostNetwork != "" {
		t.Fatal("Machines did not open the main workspace")
	}
	m.screen = "job-details"
	m.jobs = []*job{{id: 1, projectID: m.current.ID, kind: jobDiscover, targets: []string{main.currentHost()}, status: statusDone}}
	m.reconMenuFocus = true
	next, _ = m.updateJobDetails("enter")
	results := next.(model)
	if results.screen != "desk" || results.reconMenuFocus {
		t.Fatal("discovery results did not focus the shared workspace")
	}
	if main.viewDesk(150) != results.viewDesk(150) {
		t.Fatal("main screen differs from the discovery results workspace")
	}
}
