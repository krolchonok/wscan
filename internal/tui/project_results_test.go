package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/storage"
)

func projectResultsFixture() model {
	now := time.Now()
	old := domain.Finding{TemplateID: "check/CVE-2024-12345", Name: "CVE first", MatchedAt: "http://10.1.0.1:80/", Target: "10.1.0.1", Severity: "high", Time: now.Add(-time.Hour)}
	fresh := old
	fresh.Time = now
	fresh.Description = "updated"
	critical := domain.Finding{TemplateID: "nmap/vnc-info", Name: "vnc", MatchedAt: "nse://10.2.0.2:5900/vnc-info", Target: "10.2.0.2", Severity: "info", Evidence: "WARNING: Server does not require authentication", Time: now}
	info := domain.Finding{TemplateID: "discovery", Name: "server version", MatchedAt: "http://10.2.0.2:80/", Target: "10.2.0.2", Severity: "info", Time: now}
	return model{current: domain.Project{ID: 1, Name: "lab"}, screen: "networks", width: 160, height: 30, hostNetwork: "10.1.0.0/24", hostOrder: []string{"10.1.0.1"}, inventory: map[string]*hostInfo{
		"10.1.0.1": {services: []domain.Service{{Host: "10.1.0.1", Port: 80, Protocol: "tcp"}}, findings: []domain.Finding{old, fresh}},
		"10.2.0.2": {services: []domain.Service{{Host: "10.2.0.2", Port: 5900, Protocol: "tcp"}}, findings: []domain.Finding{critical, info}},
		"alias":    {findings: []domain.Finding{fresh}},
	}}
}

func TestADResultsDisplayHostInsteadOfEntireScanScope(t *testing.T) {
	scope := "10.0.0.0/24 10.0.0.1 10.0.0.16 10.0.0.133"
	for _, test := range []struct {
		matched, template, want string
	}{
		{"10.0.0.133", "adscan-role-windows-host", "10.0.0.133"},
		{"10.0.0.16", "adscan-smb-anonymous-access", "10.0.0.16"},
		{scope, "adscan-recon-summary", "Область: 10.0.0.0/24"},
		{"", "adscan-recon-summary", "Область: 10.0.0.0/24"},
		{"nse://10.0.0.123", "nmap/smb-protocols", "nse://10.0.0.123"},
		{"nse://10.0.0.10:3389/rdp-ntlm-info", "nmap/rdp-ntlm-info", "10.0.0.10:3389"},
	} {
		f := domain.Finding{Target: scope, MatchedAt: test.matched, TemplateID: test.template, Name: "Результат", Severity: "info"}
		if got := projectResultLocation(f); got != test.want {
			t.Fatalf("%s: location %q, want %q", test.template, got, test.want)
		}
		if strings.Contains(projectResultLabel(f), scope) {
			t.Fatal("row repeats the entire scan scope")
		}
		m := model{findingDetail: &f}
		if strings.Contains(strings.Join(m.projectResultDetailLines(300), "\n"), scope) {
			t.Fatal("overview repeats the entire scan scope")
		}
		if f.Target != scope {
			t.Fatal("display changed saved finding scope")
		}
	}
}
func TestProjectResultsAcrossNetworksAndDedup(t *testing.T) {
	m := projectResultsFixture()
	got, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("5")})
	m = got.(model)
	fs := m.deskFindings()
	if cmd != nil || m.screen != "project-results" || len(fs) != 2 || domain.EffectiveSeverity(fs[0]) != "critical" || fs[1].Description != "updated" {
		t.Fatalf("%s %+v", m.screen, fs)
	}
	if m.findingDetail == nil || !strings.Contains(m.findingDetail.MatchedAt, "5900") {
		t.Fatal("global list did not select highest severity")
	}
	if !strings.Contains(m.navigationLine(), "5 Результаты") || !strings.Contains(m.viewFindingDetails(150), "10.2.0.2:5900") {
		t.Fatal("navigation or result address missing")
	}
	got, _ = m.updateProjectResults("down")
	m = got.(model)
	if m.findingDetail.TemplateID != "check/CVE-2024-12345" {
		t.Fatal("could not move between hosts without opening hosts")
	}
	got, _ = m.updateProjectResults("esc")
	if got.(model).screen != "networks" {
		t.Fatal("lost return screen")
	}
}
func TestProjectResultsFiltersSearchAndEmptyState(t *testing.T) {
	m := projectResultsFixture()
	m.openProjectResults()
	got, _ := m.updateProjectResults("f")
	m = got.(model)
	if m.projectResultsFilter != "risk" || len(m.deskFindings()) != 2 {
		t.Fatal("risk filter failed")
	}
	got, _ = m.updateProjectResults("/")
	m = got.(model)
	if m.screen != "input" || m.inputAction != "project-results-search" {
		t.Fatal("search input missing")
	}
	m.input = "CVE-2024-12345"
	got, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = got.(model)
	if len(m.deskFindings()) != 1 || m.findingDetail.Description != "updated" {
		t.Fatal("CVE search failed")
	}
	m.projectResultsSearch = "no matches"
	m.refreshProjectResultSelection()
	if m.findingDetail != nil || len(m.deskFindings()) != 0 {
		t.Fatal("empty filter retained stale finding")
	}
	if !strings.Contains(m.viewFindingDetails(150), "Находка не выбрана") {
		t.Fatal("empty view failed")
	}
	got, _ = m.updateProjectResults("c")
	m = got.(model)
	if len(m.deskFindings()) != 2 || m.findingDetail == nil {
		t.Fatal("filter reset failed")
	}
}
func TestProjectResultsAllPortsAndReturn(t *testing.T) {
	m := projectResultsFixture()
	m.openProjectResults()
	got, _ := m.updateProjectResults("v")
	m = got.(model)
	rows := m.serviceInventoryRows()
	if m.screen != "service-inventory" || len(rows) != 2 {
		t.Fatal("all ports view stayed scoped to one subnet")
	}
	if len(filterServiceInventory(rows, "5900")) != 1 {
		t.Fatal("port filter failed")
	}
	got, _ = m.updateServiceInventory("esc")
	m = got.(model)
	if m.screen != "project-results" || m.serviceInventoryProject {
		t.Fatal("could not return to global findings")
	}
	m.screen = "desk"
	m.serviceIndex = 0
	if len(m.deskFindings()) != 1 {
		t.Fatal("global mode leaked into per-service findings")
	}
}

func TestProjectResultsLiveRefresh(t *testing.T) {
	m := projectResultsFixture()
	m.ctx = context.Background()
	store, err := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, err := store.CreateProject(m.ctx, "lab")
	if err != nil {
		t.Fatal(err)
	}
	m.store = store
	m.current.ID = id
	m.openProjectResults()
	selected := *m.findingDetail
	f := domain.Finding{TemplateID: "new/critical", Name: "new result", MatchedAt: "http://10.3.0.3:8080/", Target: "10.3.0.3", Severity: "critical", Time: time.Now()}
	m.mergeResult(engine.Result{Findings: []domain.Finding{f}}, []string{f.Target})
	if len(m.deskFindings()) != 3 || m.findingDetail.TemplateID != selected.TemplateID {
		t.Fatal("new result lost previous selection or was hidden by subnet scope")
	}
	m.projectResultsSearch = "unknown"
	m.refreshProjectResultSelection()
	f.Name = "unknown"
	f.TemplateID = "new/matching"
	m.mergeResult(engine.Result{Findings: []domain.Finding{f}}, []string{f.Target})
	if m.findingDetail == nil || m.findingDetail.Name != "unknown" {
		t.Fatal("new matching result did not populate empty filtered view")
	}
}
func TestProjectResultPortsSelectHostsAcrossNetworks(t *testing.T) {
	m := projectResultsFixture()
	m.openProjectResults()
	got, _ := m.updateProjectResults("v")
	m = got.(model)
	got, _ = m.updateServiceInventory("a")
	m = got.(model)
	got, _ = m.updateServiceInventory("enter")
	m = got.(model)
	if len(m.actionHosts) != 2 {
		t.Fatal("selected hosts outside current subnet were lost")
	}
}
