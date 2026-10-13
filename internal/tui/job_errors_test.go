package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

func TestJobErrorsAccessibleWithSidebarAndAllMessagesVisible(t *testing.T) {
	m := model{screen: "job-details", width: 160, height: 40, sidebarEnabled: true, current: domain.Project{ID: 1, Name: "project"}, jobs: []*job{{id: 10, projectID: 1, result: &engine.Result{Errors: []string{"DNS domain missing", "10.0.0.16:445 · smb-os-discovery: encrypt nil", "10.0.0.123:445 · MS17-010: timeout"}}}}}
	if !strings.Contains(ansi.Strip(m.View()), "Ошибки (3)") {
		t.Fatal("error tab is hidden")
	}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRight})
	m = next.(model)
	if !m.jobDetailErrors || m.reconMenuFocus {
		t.Fatal("sidebar captured error-tab navigation")
	}
	view := ansi.Strip(m.View())
	for _, message := range m.jobs[0].result.Errors {
		if !strings.Contains(view, message) {
			t.Fatalf("error missing: %s\n%s", message, view)
		}
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRight})
	m = next.(model)
	if !m.jobDetailRaw || m.jobDetailErrors {
		t.Fatal("cannot switch from errors to journal")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyLeft})
	m = next.(model)
	if !m.jobDetailErrors {
		t.Fatal("cannot return to errors")
	}
}

func TestJobErrorsWrapAndScrollToEndAtSidebarWidth(t *testing.T) {
	m := model{screen: "job-details", width: 80, height: 18, sidebarEnabled: true, current: domain.Project{ID: 1}, jobDetailErrors: true, jobs: []*job{{id: 1, result: &engine.Result{Errors: []string{strings.Repeat("error detail ", 150) + "FINAL_ERROR_DETAIL"}}}}}
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnd})
	m = next.(model)
	view := ansi.Strip(m.View())
	if !strings.Contains(view, "FINAL_ERROR_DETAIL") {
		t.Fatal("last error text cannot be reached")
	}
	for _, line := range strings.Split(m.View(), "\n") {
		if ansi.StringWidth(line) != m.width {
			t.Fatal("long error broke terminal layout")
		}
	}
}

func TestLegacyADJobErrorsRecoveredAfterRestart(t *testing.T) {
	j := &job{journal: []string{"20:23:01  DNS SRV пропущен: домен не раскрыт", "20:23:15  Некоторые SMB/RDP-проверки завершились с ошибкой: smb-os-discovery: encrypt nil\nstack traceback", "20:23:15  Некоторые SMB/RDP-проверки завершились с ошибкой: smb-vuln-ms17-010: encrypt nil"}}
	if errors := j.taskErrors(); len(errors) != 3 || !strings.Contains(errors[1], "stack traceback") {
		t.Fatalf("legacy error details lost: %v", errors)
	}
	// A new completed snapshot explicitly records zero errors; its coverage
	// skips must not be reconstructed as errors from the legacy journal.
	j.checkErrors = []string{}
	if errors := j.taskErrors(); len(errors) != 0 {
		t.Fatal("new zero-error snapshot was mistaken for a legacy job")
	}
}
