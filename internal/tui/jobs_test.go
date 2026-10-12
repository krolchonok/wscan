package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

func TestRunningJobVisibleAfterSwitchingProject(t *testing.T) {
	m := model{ctx: context.Background(), screen: "desk", width: 100, height: 30,
		current:   domain.Project{ID: 1, Name: "original"},
		projects:  []domain.Project{{ID: 1, Name: "original"}, {ID: 2, Name: "other"}},
		jobEvents: make(chan jobEvent, 8)}
	finished := make(chan struct{})
	m.launch(jobDiscover, "scan-localhost", []string{"localhost"}, func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		defer close(finished)
		emit("Порты: localhost", 5, 10)
		<-ctx.Done()
		return engine.Result{}, ctx.Err()
	})
	defer func() { m.jobs[0].cancel(); <-finished }()
	m.applyJobEvent(<-m.jobEvents)
	m.current = m.projects[1]
	m.screen = "settings"
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	m = next.(model)
	view := ansi.Strip(m.View())
	if m.screen != "jobs" || !strings.Contains(view, "scan-localhost") || !strings.Contains(view, "original") || !strings.Contains(view, "50%") || !strings.Contains(view, "5/10") {
		t.Fatalf("running task missing from global jobs window:\n%s", view)
	}
	next, _ = m.updateJobs("esc")
	if next.(model).screen != "settings" {
		t.Fatal("jobs did not return to previous screen")
	}
}

func TestViewFillsTerminalAndKeepsFooterAfterResize(t *testing.T) {
	for _, screen := range []string{"projects", "desk", "jobs", "job-details", "action-menu", "disc-options", "settings", "catalog-groups"} {
		for _, size := range [][2]int{{100, 24}, {140, 45}, {55, 18}} {
			m := model{screen: screen, width: size[0], height: size[1], current: domain.Project{ID: 1, Name: "test"},
				hostOrder: []string{"localhost"}, inventory: map[string]*hostInfo{"localhost": {}},
				jobs: []*job{{id: 1, projectID: 1, label: "scan", status: statusRunning, stage: "Порты", completed: 2, total: 4, started: time.Now()}}}
			view := m.View()
			lines := strings.Split(view, "\n")
			if len(lines) != size[1] {
				t.Fatalf("%s: got %d rows, want %d", screen, len(lines), size[1])
			}
			for _, line := range lines {
				if ansi.StringWidth(line) != size[0] {
					t.Fatalf("%s: line width %d, want %d", screen, ansi.StringWidth(line), size[0])
				}
			}
			if !strings.Contains(ansi.Strip(lines[len(lines)-1]), "↑/↓") && screen != "settings" && screen != "job-details" {
				t.Fatalf("%s: footer was clipped", screen)
			}
			modal := screen == "action-menu" || screen == "disc-options"
			if modal {
				if !strings.Contains(ansi.Strip(view), "└") && !strings.Contains(ansi.Strip(view), "╰") {
					t.Fatalf("%s: centered dialog has no bottom border", screen)
				}
			} else if !strings.Contains(ansi.Strip(lines[size[1]-4]), "╰") && !strings.Contains(ansi.Strip(lines[size[1]-4]), "└") {
				t.Fatalf("%s: panel did not stretch to bottom:\n%s", screen, ansi.Strip(view))
			}
		}
	}
}

func TestOtherProjectCompletionDoesNotMixInventory(t *testing.T) {
	m := model{current: domain.Project{ID: 2}, jobs: []*job{{id: 1, projectID: 1, targets: []string{"localhost"}}}}
	m.applyJobEvent(jobEvent{id: 1, done: true, result: engine.Result{Services: []domain.Service{{Host: "localhost", Port: 80}}}})
	if len(m.inventory) != 0 || m.jobs[0].status != statusDone {
		t.Fatal("other project's result changed current inventory")
	}
}

func TestGlobalJobsShortcutSelectsLastTask(t *testing.T) {
	for _, count := range []int{0, 1, 30} {
		m := model{screen: "desk", width: 100, height: 24, current: domain.Project{ID: 1}}
		for i := 0; i < count; i++ {
			m.jobs = append(m.jobs, &job{id: i + 1, label: "task", status: statusDone})
		}
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
		m = next.(model)
		if m.screen != "jobs" || m.jobIndex != max(0, count-1) {
			t.Fatalf("%d tasks: index=%d screen=%s", count, m.jobIndex, m.screen)
		}
		if count > 0 && !strings.Contains(ansi.Strip(m.View()), "#"+fmt.Sprint(count)+" ") {
			t.Fatal("latest task outside visible window")
		}
	}
}

func TestDiscoveryTaskShowsHostsAndPortsInsteadOfEmptyFindings(t *testing.T) {
	m := resultScopeFixture()
	res := engine.Result{RunID: 42, LiveHosts: []string{"10.0.0.10", "10.0.0.10", "10.0.0.20"}, Services: []domain.Service{
		{Host: "10.0.0.10", Port: 80, Protocol: "tcp", State: "open"},
		{Host: "10.0.0.10", Port: 445, Protocol: "tcp", State: "open"},
		{Host: "10.0.0.20", Port: 80, Protocol: "tcp", State: "open"},
		{Host: "10.0.0.20", Port: 80, Protocol: "tcp", State: "open"},
		{Host: "10.0.0.20", Port: 22, Protocol: "tcp", State: "closed"},
	}}
	j := &job{id: 1, projectID: 1, kind: jobDiscover, label: "discovery", status: statusDone, result: &res, targets: []string{"10.0.0.0/24"}}
	m.jobs = []*job{j}
	m.screen = "job-details"
	m.width, m.height = 160, 40
	for _, view := range []string{ansi.Strip(m.viewJobSummary(160, j)), ansi.Strip(m.viewJobs(160))} {
		if !strings.Contains(view, "Хосты: 2 · Открытые порты: 3") || strings.Contains(view, "Риски: 0") {
			t.Fatalf("misleading discovery summary:\n%s", view)
		}
	}
	if !strings.Contains(ansi.Strip(m.viewJobSummary(160, j)), "445/tcp") {
		t.Fatal("discovered port missing from details")
	}
	next, _ := m.updateJobDetails("enter")
	m = next.(model)
	if m.screen != "desk" || m.hostNetwork != "10.0.0.0/24" {
		t.Fatal("discovery opened empty finding screen instead of hosts")
	}
}
