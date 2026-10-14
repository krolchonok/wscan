package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
)

func portBrowserFixture() model {
	ssh := domain.Finding{TemplateID: "ssh-a", MatchedAt: "tcp://192.0.2.10:22", Protocol: "tcp", Severity: "high"}
	m := model{screen: "desk", current: domain.Project{ID: 1}, width: 160, height: 30,
		hostNetwork: "192.0.2.0/24", hostOrder: []string{"192.0.2.10"},
		inventory: map[string]*hostInfo{
			"192.0.2.10": {services: []domain.Service{
				{Host: "192.0.2.10", Port: 22, Name: "ssh"},
				{Host: "192.0.2.10", Port: 53, Protocol: "tcp"},
				{Host: "192.0.2.10", Port: 53, Protocol: "udp", State: "open"},
				{Host: "192.0.2.10", Port: 80, Protocol: "tcp", State: "closed"},
				{Host: "192.0.2.10", Port: 81, Protocol: "udp", State: "open|filtered"},
			}, findings: []domain.Finding{ssh,
				{TemplateID: "dns-tcp", MatchedAt: "tcp://192.0.2.10:53", Protocol: "tcp", Severity: "info"},
				{TemplateID: "dns-udp", MatchedAt: "udp://192.0.2.10:53", Protocol: "udp", Severity: "high"}}},
			"alias.test": {services: []domain.Service{{Host: "192.0.2.10", Port: 22, Protocol: "TCP", Name: "ssh"}}, findings: []domain.Finding{ssh}},
			"192.0.2.20": {services: []domain.Service{{Host: "192.0.2.20", Port: 22, Protocol: "tcp", Name: "ssh"}}, findings: []domain.Finding{
				{TemplateID: "ssh-b", MatchedAt: "tcp://192.0.2.20:22", Protocol: "tcp", Severity: "info"}}},
			"198.51.100.30": {services: []domain.Service{{Host: "198.51.100.30", Port: 22, Protocol: "tcp", Name: "ssh"}}},
			"198.51.100.40": {services: []domain.Service{{Host: "198.51.100.40", Port: 2222, Protocol: "tcp"}}},
		}}
	return m
}

func TestProjectPortsIncludeHostsWithoutFindingsAndDeduplicateAliases(t *testing.T) {
	m := portBrowserFixture()
	ports := m.projectPorts()
	if len(ports) != 4 || ports[0].port != 22 || ports[0].protocol != "tcp" || len(ports[0].hosts) != 3 {
		t.Fatalf("wrong grouped open ports: %+v", ports)
	}
	if ports[0].hosts[2].host != "198.51.100.30" || len(m.portHostFindings(ports[0].hosts[2])) != 0 {
		t.Fatal("host without findings or outside the selected subnet was omitted")
	}
	for _, protocol := range []string{"tcp", "udp"} {
		fs := m.portScopedFindings(resultScope{port: 53, protocol: protocol})
		if len(fs) != 1 || fs[0].TemplateID != "dns-"+protocol {
			t.Fatalf("transport results mixed: %s %+v", protocol, fs)
		}
	}
	for _, filter := range []string{"22", "22/tcp", "ssh"} {
		m.portBrowserFilter = filter
		if groups := m.filteredProjectPorts(); len(groups) != 1 || groups[0].port != 22 {
			t.Fatalf("port search %q matched a different port: %+v", filter, groups)
		}
	}
}

func TestPortBrowserNavigationScopesResultsAndReturns(t *testing.T) {
	m := portBrowserFixture()
	m.sidebarEnabled = true
	m.reconMenuIndex = 12
	next, cmd := m.runReconAction()
	m = next.(model)
	if cmd != nil || m.screen != "port-browser" || len(m.jobs) != 0 {
		t.Fatal("port browser did not open without starting a task")
	}
	for _, key := range []tea.KeyType{tea.KeyRight, tea.KeyDown, tea.KeyEnter} {
		next, _ = m.Update(tea.KeyMsg{Type: key})
		m = next.(model)
	}
	if m.screen != "project-results" || m.resultsScope.host != "192.0.2.20" || m.resultsScope.port != 22 {
		t.Fatalf("wrong host/port result scope: %+v", m.resultsScope)
	}
	if fs := m.filteredProjectFindings(); len(fs) != 1 || fs[0].TemplateID != "ssh-b" {
		t.Fatalf("results escaped selected host/port: %+v", fs)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(model)
	if m.screen != "port-browser" || m.portBrowserHost != "192.0.2.20" {
		t.Fatal("result return lost the selected host")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	m = next.(model)
	if len(m.filteredProjectFindings()) != 2 || m.resultsScope.host != "" || m.resultsScope.port != 22 {
		t.Fatal("all-port results include another port or duplicated aliases")
	}
}

func TestPortBrowserFilterClearsAndHostShortcutSelectsPort(t *testing.T) {
	m := portBrowserFixture()
	m.openPortBrowser()
	next, _ := m.updatePortBrowser("/")
	m = next.(model)
	m.input = "53/udp"
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if groups := m.filteredProjectPorts(); m.screen != "port-browser" || len(groups) != 1 || groups[0].protocol != "udp" {
		t.Fatal("port filter was not applied")
	}
	next, _ = m.updatePortBrowser("h")
	m = next.(model)
	if m.screen != "desk" || m.hostNetwork != "" || m.currentHost() != "192.0.2.10" || m.servicesFor(m.currentHost())[m.serviceIndex].Protocol != "udp" {
		t.Fatal("host shortcut did not select the matching UDP port")
	}
	m.openPortBrowser()
	m.portBrowserFilter = "missing"
	next, _ = m.updatePortBrowser("/")
	m = next.(model)
	m.input = ""
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if m.portBrowserFilter != "" || len(m.filteredProjectPorts()) != 4 {
		t.Fatal("empty input cannot clear the port filter")
	}
}

func TestPortBrowserRestoresOriginalResultsScopeWithoutReturnLoop(t *testing.T) {
	m := portBrowserFixture()
	m.screen = "networks"
	m.openScopedResults(resultScope{host: "192.0.2.20"})
	m.projectResultsFilter = "all"
	m.refreshProjectResultSelection()
	next, _ := m.updateProjectResults("p")
	m = next.(model)
	next, _ = m.updatePortBrowser("r")
	m = next.(model)
	if len(m.filteredProjectFindings()) != 2 {
		t.Fatal("port results did not replace the original single-host scope")
	}
	next, _ = m.updateProjectResults("esc")
	m = next.(model)
	next, _ = m.updatePortBrowser("esc")
	m = next.(model)
	if m.screen != "project-results" || m.resultsScope.host != "192.0.2.20" || m.resultsScope.port != 0 || len(m.filteredProjectFindings()) != 1 {
		t.Fatalf("original result scope was lost: %+v", m.resultsScope)
	}
	next, _ = m.updateProjectResults("esc")
	if next.(model).screen != "networks" {
		t.Fatal("return from original results loops back to the port browser")
	}
}

func TestPortBrowserSelectionSurvivesNewPortsAndHosts(t *testing.T) {
	m := portBrowserFixture()
	m.openPortBrowser()
	m.portBrowserHost = "192.0.2.20"
	m.inventory["192.0.2.1"] = &hostInfo{services: []domain.Service{
		{Host: "192.0.2.1", Port: 21, Protocol: "tcp"},
		{Host: "192.0.2.1", Port: 22, Protocol: "tcp"}}}
	ports := m.filteredProjectPorts()
	group := ports[m.selectedProjectPort(ports)]
	if group.port != 22 || group.hosts[m.selectedPortHost(group)].host != "192.0.2.20" {
		t.Fatal("incoming discovery results moved the selected port or host")
	}
}

func TestPortBrowserFitsWindowAndKeepsSelectedHostVisible(t *testing.T) {
	for _, sidebar := range []bool{false, true} {
		for _, width := range []int{48, 80, 100, 160, 240} {
			for _, height := range []int{18, 30} {
				t.Run(fmt.Sprintf("%v-%dx%d", sidebar, width, height), func(t *testing.T) {
					m := portBrowserFixture()
					m.sidebarEnabled, m.width, m.height = sidebar, width, height
					m.openPortBrowser()
					m.portBrowserFocus, m.portBrowserHost = 1, "198.51.100.30"
					view := m.View()
					if lipgloss.Height(view) != height || lipgloss.Width(view) != width || !strings.Contains(ansi.Strip(view), m.portBrowserHost) {
						t.Fatalf("port browser layout lost dimensions or selected host:\n%s", ansi.Strip(view))
					}
				})
			}
		}
	}
}
