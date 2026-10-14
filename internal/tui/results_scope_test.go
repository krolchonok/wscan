package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"strings"
	"testing"
	"time"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

func resultScopeFixture() model {
	now := time.Now()
	host := "10.0.0.10"
	f := func(id, state, evidence string, ts time.Time) domain.Finding {
		return domain.Finding{Target: host, MatchedAt: "ad://" + host + "/" + id, TemplateID: "ad-access/coercion/" + id, Name: id, MatcherName: state, Severity: "info", Evidence: evidence, Time: ts}
	}
	old := []domain.Finding{f("smb", "observed", "TCP", now.Add(-time.Hour)), f("callback/printerbug/ntlm-authenticate", "observed", "identity", now.Add(-time.Hour+time.Second))}
	fresh := []domain.Finding{f("smb", "observed", "TCP", now), f("smb-auth", "denied", "open smb session: permission denied", now.Add(time.Millisecond))}
	all := append(append([]domain.Finding(nil), old...), fresh...)
	unrelated := domain.Finding{Target: host, TemplateID: "web", MatchedAt: "http://" + host + ":80", Severity: "high", Name: "Web risk", Time: now}
	return model{current: domain.Project{ID: 1, Name: "lab"}, screen: "desk", width: 120, height: 32, hostOrder: []string{host}, inventory: map[string]*hostInfo{
		host:        {services: []domain.Service{{Host: host, Port: 445, Protocol: "tcp"}, {Host: host, Port: 80, Protocol: "tcp"}}, findings: append(all, unrelated)},
		"10.0.0.20": {findings: []domain.Finding{{Target: "10.0.0.20", MatchedAt: "tcp://10.0.0.20:22", TemplateID: "ssh", Severity: "high", Name: "Other host"}}},
	}, history: []domain.Run{{ID: 2, ProjectID: 1, Findings: fresh}, {ID: 1, ProjectID: 1, Findings: old}}}
}
func TestResultsAreGroupedInHostAndPortViews(t *testing.T) {
	m := resultScopeFixture()
	host := m.currentHost()
	if n := len(m.findingsFor(host)); n != 2 {
		t.Fatalf("host has %d results instead of Coerce + Web", n)
	}
	rows := m.findingsForService(host, m.servicesFor(host)[0])
	if len(rows) != 1 || rows[0].MatcherName != "denied" {
		t.Fatalf("SMB port did not include one latest Coerce conclusion: %+v", rows)
	}
	if !m.openFinding() || m.screen != "project-results" || m.resultsScope.service.Port != 445 {
		t.Fatal("port details did not use unified screen")
	}
	if len(m.deskFindings()) != 1 {
		t.Fatal("port scope leaked other results")
	}
	next, _ := m.updateProjectResults("esc")
	m = next.(model)
	if m.screen != "desk" {
		t.Fatal("lost desk return")
	}
}
func TestHistoryOpensOnlySelectedRunAndProtectsNewerResults(t *testing.T) {
	m := resultScopeFixture()
	m.screen = "history"
	m.historyIndex = 1
	next, _ := m.updateHistory("enter")
	m = next.(model)
	if m.resultsScope.runID != 1 || len(m.deskFindings()) != 1 || m.findingDetail.MatcherName != "response" {
		t.Fatal("history mixed separate runs")
	}
	members := m.resultDeleteMembers(*m.findingDetail)
	if len(members) != 2 {
		t.Fatal("deleting historical group would include newer report")
	}
	next, _ = m.updateProjectResults("esc")
	m = next.(model)
	if m.screen != "history" {
		t.Fatal("history return lost")
	}
	m.openProjectResults()
	var coerce domain.Finding
	for _, f := range m.projectFindings() {
		if f.TemplateID == "ui/coercion-summary" {
			coerce = f
		}
	}
	if coerce.MatcherName != "denied" {
		t.Fatal("old success polluted current project")
	}
}
func TestDeletionAlsoUpdatesTaskSummary(t *testing.T) {
	m := resultScopeFixture()
	fs := m.history[0].Findings
	m.jobs = []*job{{projectID: 1, runID: 2, result: &engine.Result{RunID: 2, Findings: append([]domain.Finding(nil), fs...)}}}
	m.openRunResults(2)
	next, _ := m.applyResultDeleted(resultDeleted{projectID: 1, findings: fs, count: len(fs)})
	m = next.(model)
	if len(m.jobs[0].result.Findings) != 0 || len(m.scopedResults()) != 0 {
		t.Fatal("deleted detectors remain in task/history views")
	}
}
func TestNavigationAndContextHelpPreserveEditors(t *testing.T) {
	m := resultScopeFixture()
	for _, screen := range []string{"desk", "project-results", "job-details", "history", "service-inventory"} {
		m.screen = screen
		next, ok := m.navigateWorkspace("5")
		if !ok || next.screen != "project-results" || next.resultsScope.runID != 0 {
			t.Fatalf("navigation from %s", screen)
		}
		next, ok = m.navigateWorkspace("p")
		if !ok || next.screen != "port-browser" || next.portBrowserReturn != screen {
			t.Fatalf("port navigation from %s", screen)
		}
	}
	for _, screen := range []string{"input", "coerce-port-confirm", "mssql-console", "cred-delete-confirm"} {
		m.screen = screen
		_, ok := m.navigateWorkspace("5")
		if ok {
			t.Fatalf("navigation intercepted keys in %s", screen)
		}
	}
	m.screen = "project-results"
	m.resultDeleteConfirm = true
	if _, ok := m.navigateWorkspace("5"); ok {
		t.Fatal("navigation bypassed deletion confirmation")
	}
	m.resultDeleteConfirm = false
	m.width, m.height = 60, 18
	m.helpReturn = "project-results"
	m.screen = "help"
	if !strings.Contains(strings.Join(m.helpLines(60), "\n"), "Del/d удалить") {
		t.Fatal("help does not describe result screen")
	}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	m = next.(model)
	if m.helpOffset == 0 {
		t.Fatal("long context help cannot scroll")
	}
}

func TestLateDeletionDoesNotResetNewDialog(t *testing.T) {
	m := resultScopeFixture()
	m.openRunResults(2)
	next, _ := m.requestResultDelete(false)
	m = next.(model)
	earlier := m.resultDeleteGeneration
	next, _ = m.confirmResultDelete("esc")
	m = next.(model)
	next, _ = m.requestResultDelete(false)
	m = next.(model)
	next, _ = m.applyResultDeleted(resultDeleted{projectID: m.current.ID, generation: earlier, findings: m.history[0].Findings})
	m = next.(model)
	if !m.resultDeleteConfirm || len(m.history[0].Findings) == 0 {
		t.Fatal("late completion changed a newer dialog")
	}
}
