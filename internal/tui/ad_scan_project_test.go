package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wscan/internal/adscan"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/storage"
)

func TestADScanDestinationChoice(t *testing.T) {
	m := model{current: domain.Project{ID: 42, Name: "existing"}, screen: "desk", width: 110, height: 30}
	m.openADScan()
	if m.adScanNewProject || !strings.Contains(m.viewADScan(100), "текущий проект") {
		t.Fatal("opened project should be the default destination")
	}
	got, _ := m.updateADScan("p")
	m = got.(model)
	if !m.adScanNewProject || !strings.Contains(m.viewADScan(100), "новый проект") {
		t.Fatal("new project choice missing")
	}
	got, _ = m.updateADScan("p")
	m = got.(model)
	if m.adScanNewProject {
		t.Fatal("could not return to existing project")
	}
	m.adScanRunning = true
	got, _ = m.updateADScan("p")
	if got.(model).adScanNewProject {
		t.Fatal("destination changed during scan")
	}
	m = model{screen: "projects"}
	m.openADScan()
	got, _ = m.updateADScan("p")
	m = got.(model)
	if !m.adScanNewProject || !strings.Contains(m.message, "не открыт") {
		t.Fatal("no-project mode must stay new")
	}
}
func TestADExistingProjectPreservesInventoryAndSettings(t *testing.T) {
	ctx := context.Background()
	store, e := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	id, e := store.CreateProjectWithTargets(ctx, "existing", []string{"192.0.2.9"})
	if e != nil {
		t.Fatal(e)
	}
	if e = store.SetLimits(ctx, id, 3, 2); e != nil {
		t.Fatal(e)
	}
	oldRun, e := store.StartRun(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	oldService := domain.Service{Host: "192.0.2.9", Port: 443, Protocol: "tcp", Name: "https", Product: "nginx", Version: "1.24"}
	if e = store.SaveService(ctx, oldRun, oldService); e != nil {
		t.Fatal(e)
	}
	oldFinding := domain.Finding{TemplateID: "existing/check", Target: oldService.Host, MatchedAt: "https://192.0.2.9:443/", Name: "old finding", Severity: "info", Time: time.Now()}
	if e = store.SaveFinding(ctx, oldRun, oldFinding); e != nil {
		t.Fatal(e)
	}
	if e = store.FinishRun(ctx, oldRun, "completed"); e != nil {
		t.Fatal(e)
	}
	m := model{ctx: ctx, store: store, current: domain.Project{ID: id, Name: "existing"}}
	details := adscan.Result{Hosts: []adscan.Host{{Address: "192.0.2.10"}, {Address: "192.0.2.10"}}}
	gotID, name, e := m.adResultProject(ctx, "192.0.2.0/24", details)
	if e != nil || gotID != id || name != "existing" {
		t.Fatalf("%d %s %v", gotID, name, e)
	}
	ps, e := store.ListProjects(ctx)
	if e != nil || len(ps) != 1 || ps[0].RPS != 3 || ps[0].Concurrency != 2 || len(ps[0].Targets) != 3 {
		t.Fatalf("%+v %v", ps, e)
	}
	newRun, e := store.StartRun(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	newService := domain.Service{Host: "192.0.2.10", Port: 389, Protocol: "tcp", Name: "ldap"}
	if e = store.SaveService(ctx, newRun, newService); e != nil {
		t.Fatal(e)
	}
	if e = store.FinishRun(ctx, newRun, "completed"); e != nil {
		t.Fatal(e)
	}
	m.jobs = []*job{{id: 1, kind: jobAD, projectID: id, status: statusRunning}}
	m.adScanJobID = 1
	m.adScanRunning = true
	m.applyJobEvent(jobEvent{id: 1, done: true, projectID: id, projectName: name, adResult: &details, result: engine.Result{RunID: newRun, Services: []domain.Service{newService}}})
	if m.current.ID != id || len(m.servicesFor(oldService.Host)) != 1 || len(m.findingsFor(oldService.Host)) != 1 || len(m.servicesFor(newService.Host)) != 1 {
		t.Fatal("AD results replaced existing project inventory")
	}
	if !strings.Contains(strings.Join(m.jobs[0].journal, "\n"), "Дополнен проект") {
		t.Fatal("existing project falsely reported as created")
	}
	m.adScanNewProject = true
	newID, _, e := m.adResultProject(ctx, "192.0.2.0/24", details)
	if e != nil || newID == id {
		t.Fatal("explicit new-project mode reused existing project", e)
	}
	ps, e = store.ListProjects(ctx)
	if e != nil || len(ps) != 2 {
		t.Fatalf("%+v %v", ps, e)
	}
}
func TestADMissingCurrentProjectDoesNotCreateReplacement(t *testing.T) {
	ctx := context.Background()
	store, e := storage.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	m := model{ctx: ctx, store: store, current: domain.Project{ID: 999, Name: "deleted"}}
	id, _, e := m.adResultProject(ctx, "192.0.2.0/24", adscan.Result{})
	if e == nil || id != 0 {
		t.Fatal("missing destination silently created a project")
	}
	ps, e := store.ListProjects(ctx)
	if e != nil || len(ps) != 0 {
		t.Fatal("unexpected project created")
	}
}

func TestADScanHasSingleProjectEntry(t *testing.T) {
	m := model{current: domain.Project{ID: 42, Name: "existing", Targets: []string{"192.0.2.10"}}, screen: "recon", width: 110, height: 24}
	m.reconMenuIndex = 1
	got, cmd := m.runReconAction()
	m = got.(model)
	if cmd != nil || m.screen != "ad-menu" {
		t.Fatal("AD section missing")
	}
	got, cmd = m.updateADMenu("enter")
	m = got.(model)
	if cmd != nil || m.screen != "guided-scan" || m.wizardProfile != 1 || len(m.jobs) != 0 {
		t.Fatal("AD entry must open setup without scanning")
	}
	got, _ = m.updateGuidedScan("enter")
	m = got.(model)
	if m.wizardStep != 2 {
		t.Fatal("AD setup should skip generic profile selection")
	}
	got, _ = m.updateGuidedScan("esc")
	m = got.(model)
	if m.wizardStep != 0 {
		t.Fatal("AD back should return to scope")
	}
}

func TestInteractionMenuDoesNotDuplicateAD(t *testing.T) {
	m := model{width: 110, height: 40, screen: "interaction-menu"}
	got, _ := m.updateInteractionMenu("end")
	m = got.(model)
	if m.interactionIndex != 11 || strings.Contains(m.viewInteractionMenu(100), "AD Scan") || strings.Contains(m.viewInteractionMenu(100), "Coerce / Responder") {
		t.Fatal("AD duplicates remain in interaction tools")
	}
	got, _ = m.updateInteractionMenu("home")
	if got.(model).interactionIndex != 0 {
		t.Fatal("Home did not return to first tool")
	}
}

func TestGenericScanProfilesDoNotDuplicateAD(t *testing.T) {
	m := model{width: 110, height: 30, screen: "guided-scan", wizardStep: 1}
	if strings.Contains(m.viewGuidedScan(100), "Аудит AD") {
		t.Fatal("AD still shown in generic scan")
	}
	for i, profile := range scanProfileChoices {
		m.wizardStep = 1
		m.wizardIndex = i
		got, _ := m.updateGuidedScan("enter")
		if got.(model).wizardProfile != profile || profile == 1 {
			t.Fatal("wrong generic scan profile")
		}
	}
}
