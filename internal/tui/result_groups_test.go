package tui

import (
	"context"
	"strings"
	"testing"
	"time"
	"wscan/internal/domain"
	"wscan/internal/storage"
)

func TestCoercionResultsLatestSummaryAndRawDetails(t *testing.T) {
	now := time.Now()
	host := "10.0.0.10"
	mk := func(id, state, evidence string, ts time.Time) domain.Finding {
		return domain.Finding{Target: host, MatchedAt: "ad://" + host + "/" + id, TemplateID: "ad-access/coercion/" + id, MatcherName: state, Evidence: evidence, Time: ts, Severity: "info"}
	}
	fs := []domain.Finding{mk("smb", "observed", "TCP", now.Add(-time.Hour)), mk("callback/printerbug/ntlm-authenticate", "observed", "identity", now.Add(-time.Hour+time.Second)), mk("smb", "observed", "TCP", now), mk("printerbug", "denied", "permission denied", now.Add(time.Millisecond))}
	rows := groupedProjectResults(fs)
	if len(rows) != 1 || rows[0].MatcherName != "denied" || rows[0].Severity != "error" {
		t.Fatalf("older authentication polluted summary: %+v", rows)
	}
	fs = append(fs, mk("callback/printerbug/anonymous-authenticate", "observed", "anonymous", now.Add(time.Second)))
	rows = groupedProjectResults(fs)
	if rows[0].MatcherName != "anonymous" || !strings.Contains(rows[0].Name, "учётные данные не переданы") {
		t.Fatal("anonymous interpreted as credential disclosure")
	}
	if !strings.Contains(rows[0].Response, "permission denied") {
		t.Fatal("raw evidence lost")
	}
}
func TestProjectResultsDeleteConfirmPersistAndCancel(t *testing.T) {
	m := newTestModelForSettings(t)
	m.ctx = context.Background()
	run, e := m.store.StartRun(m.ctx, m.current.ID)
	if e != nil {
		t.Fatal(e)
	}
	f := domain.Finding{Target: "10.0.0.10", MatchedAt: "tcp://10.0.0.10:445", TemplateID: "example", Name: "example", Severity: "high", Time: time.Now()}
	if e = m.store.SaveFinding(m.ctx, run, f); e != nil {
		t.Fatal(e)
	}
	m.inventory = map[string]*hostInfo{f.Target: {findings: []domain.Finding{f}}}
	m.openProjectResults()
	next, cmd := m.updateProjectResults("delete")
	m = next.(model)
	if !m.resultDeleteConfirm || cmd != nil {
		t.Fatal("must ask before deleting")
	}
	next, _ = m.updateProjectResults("esc")
	m = next.(model)
	saved, _ := m.store.Findings(m.ctx, run)
	if len(saved) != 1 {
		t.Fatal("cancel deleted result")
	}
	next, _ = m.updateProjectResults(" ")
	m = next.(model)
	if !m.projectResultsSelected[storage.FindingKey(f)] {
		t.Fatal("selection failed")
	}
	next, _ = m.updateProjectResults("delete")
	m = next.(model)
	next, cmd = m.updateProjectResults("enter")
	m = next.(model)
	if cmd == nil {
		t.Fatal("delete command missing")
	}
	next, _ = m.Update(cmd())
	m = next.(model)
	saved, _ = m.store.Findings(m.ctx, run)
	if len(saved) != 0 || len(m.projectFindings()) != 0 || m.resultDeleteConfirm {
		t.Fatal("delete not reflected in saved results and UI")
	}
}

func TestProjectResultsPagesAndDetailReturn(t *testing.T) {
	m := projectResultsFixture()
	m.openProjectResults()
	next, _ := m.updateProjectResults("enter")
	m = next.(model)
	if m.findingPane != 1 {
		t.Fatal("Enter must open separate detail")
	}
	next, _ = m.updateProjectResults("esc")
	m = next.(model)
	if m.screen != "project-results" || m.findingPane != 0 {
		t.Fatal("Esc must return to list first")
	}
	next, _ = m.updateProjectResults("i")
	m = next.(model)
	if len(m.deskFindings()) != 3 || m.projectResultsFilter != "all" {
		t.Fatal("all information must remain accessible")
	}
	for _, w := range []int{60, 100, 160} {
		m.width = w
		view := m.View()
		if !strings.Contains(view, "Del") || !strings.Contains(view, "Результаты") {
			t.Fatalf("missing actions at width %d", w)
		}
	}
}

func TestCoercionDiscoveryPartialPermissionsAndLocalReceiver(t *testing.T) {
	now := time.Now()
	fs := []domain.Finding{
		{Target: "10.0.0.10", TemplateID: "ad-access/coercion/smb", MatcherName: "observed", Time: now},
		{Target: "10.0.0.10", TemplateID: "ad-access/coercion/printerbug", MatcherName: "denied", Evidence: "open file: permission denied", Time: now.Add(time.Millisecond)},
		{Target: "10.0.0.10", TemplateID: "ad-access/coercion/mseven", MatcherName: "observed", Evidence: "RPC bind выполнен; доступность интерфейса не доказывает Coerce", Time: now.Add(time.Millisecond)},
	}
	if f := coercionSummary("10.0.0.10", fs); f.MatcherName != "discovery" {
		t.Fatalf("partial RPC permission denied is not global SMB rejection: %+v", f)
	}
	f := coercionSummary("10.0.0.16", []domain.Finding{{Target: "10.0.0.16", TemplateID: "ad-access/coercion/skipped-local", MatcherName: "skipped", Time: now}})
	if f.MatcherName != "skipped" {
		t.Fatal("local receiver exclusion presented as failed Coerce")
	}
}
