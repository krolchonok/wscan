package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"wscan/internal/app"
	"wscan/internal/engine"
)

func TestSharedJobsAppearAndCancelInTUI(t *testing.T) {
	m := newTestModelForSettings(t)
	service, err := app.NewService(m.ctx, m.store, m.cat, m.scanner)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	m.shared = service
	m.launch("fixture", "From TUI", nil, func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		emit("waiting", 1, 2)
		<-ctx.Done()
		return engine.Result{}, ctx.Err()
	})
	if len(m.jobs) != 1 || len(service.Jobs.List()) != 1 {
		t.Fatal("TUI started a separate queue")
	}
	id := m.jobs[0].id
	if err := service.Jobs.Cancel(id); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		m.syncSharedJobs()
		if m.jobs[0].status == statusCancelled {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if m.jobs[0].status != statusCancelled {
		t.Fatal("shared cancel did not reach TUI")
	}
	external, err := service.Jobs.Start(app.JobRequest{ProjectID: m.current.ID, Kind: "fixture", Label: "From Web", Source: "web"}, "", func(ctx context.Context, emit app.Reporter) (app.Outcome, error) {
		emit("external")
		<-ctx.Done()
		return app.Outcome{}, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	m.syncSharedJobs()
	if j := m.jobByID(external.ID); j == nil || j.label != "From Web" {
		t.Fatal("external job invisible in TUI")
	}
	m.jobByID(external.ID).cancel()

}

func TestGuidedOverviewAndReviewFitSmallTerminal(t *testing.T) {
	m := newTestModelForSettings(t)
	m.guided = true
	m.openProject(m.current)
	if m.screen != "overview" {
		t.Fatal("project did not open on overview")
	}
	for _, size := range [][2]int{{55, 18}, {100, 24}, {160, 40}} {
		m.width, m.height = size[0], size[1]
		text := ansi.Strip(m.View())
		if !strings.Contains(text, "Начать проверку") {
			t.Fatalf("primary action hidden at %v: %s", size, text)
		}
	}
	m.openGuidedScan()
	m.wizardIndex = 1
	m.wizardScope = "10.20.0.0/24"
	next, _ := m.updateGuidedScan("enter")
	m = next.(model)
	if m.wizardStep != 1 {
		t.Fatal("scope step did not continue")
	}
	m.wizardIndex = 1
	next, _ = m.updateGuidedScan("enter")
	m = next.(model)
	if m.wizardStep != 2 || !strings.Contains(ansi.Strip(m.viewGuidedScan(100)), "Запустить проверку") {
		t.Fatal("review does not have explicit start")
	}
	m.wizardScope = "127.0.0.1"
	next, _ = m.updateGuidedScan("enter")
	if next.(model).message == "" {
		t.Fatal("invalid AD scope started")
	}
}
func TestBrowserTerminalRunsExistingNavigation(t *testing.T) {
	m := newTestModelForSettings(t)
	service, err := app.NewService(m.ctx, m.store, m.cat, m.scanner)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	terminal, err := StartWebTerminal(context.Background(), service, t.TempDir(), 100, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	if err := terminal.Key("Enter"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		frame, _ := terminal.Frame()
		if strings.Contains(ansi.Strip(frame), "Обзор проекта") {
			return
		}
		time.Sleep(time.Millisecond)
	}
	frame, _ := terminal.Frame()
	t.Fatalf("browser TUI did not navigate: %s", ansi.Strip(frame))
}
