package tui

import (
	"github.com/charmbracelet/x/ansi"
	"strings"
	"testing"
	"wscan/internal/domain"
)

func TestFindingCardSectionsAndResize(t *testing.T) {
	m := resultScopeFixture()
	m.inventory = map[string]*hostInfo{"10.0.0.10": {findings: []domain.Finding{
		{Target: "10.0.0.10", Name: "First", TemplateID: "test/first", Severity: "high", Response: `{"proof":"saved"}`},
		{Target: "10.0.0.10", Name: "Second", TemplateID: "test/second", Severity: "info"},
	}}}
	m.openProjectResults()
	m.projectResultsFilter = "all"
	m.refreshProjectResultSelection()
	m.findingPane = 1
	m.findingRemediation = "Update the service"
	for section := 0; section < 3; section++ {
		m.findingSection = section
		for _, size := range [][2]int{{55, 18}, {100, 24}, {160, 40}} {
			m.width, m.height = size[0], size[1]
			view := ansi.Strip(m.View())
			for _, want := range []string{"Находка 1 / 2", "Строки", "Tab"} {
				if !strings.Contains(view, want) {
					t.Fatalf("section %d size %v: missing %q\n%s", section, size, want, view)
				}
			}
		}
	}
	m.findingSection = 0
	next, _ := m.updateProjectResults("tab")
	m = next.(model)
	if m.findingSection != 1 || !strings.Contains(strings.Join(m.projectResultDetailLines(80), "\n"), "saved") {
		t.Fatal("evidence tab lost saved JSON response")
	}
	next, _ = m.updateProjectResults("r")
	m = next.(model)
	if !m.findingRaw {
		t.Fatal("raw report did not open")
	}
	next, _ = m.updateProjectResults("shift+tab")
	m = next.(model)
	if m.findingRaw || m.findingSection != 0 {
		t.Fatal("section navigation did not restore overview")
	}
	next, _ = m.updateProjectResults("]")
	m = next.(model)
	if m.findingIndex != 1 || m.findingPane != 1 || m.findingOffset != 0 {
		t.Fatal("next finding did not stay in card")
	}
}

func TestFindingCardBackFollowsEntryPoint(t *testing.T) {
	for _, key := range []string{"esc", "q"} {
		m := resultScopeFixture()
		if !m.openFinding() {
			t.Fatal("cannot open host finding")
		}
		next, _ := m.updateProjectResults(key)
		m = next.(model)
		if m.screen != "desk" {
			t.Fatalf("%s from host card returned to %s", key, m.screen)
		}
	}
	m := resultScopeFixture()
	m.openProjectResults()
	next, _ := m.updateProjectResults("enter")
	m = next.(model)
	next, _ = m.updateProjectResults("esc")
	m = next.(model)
	if m.screen != "project-results" || m.findingPane != 0 {
		t.Fatal("card from list did not return to list")
	}
	// Reopening the workspace tab must not replace the original return screen.
	m, _ = m.navigateWorkspace("5")
	next, _ = m.updateProjectResults("esc")
	m = next.(model)
	if m.screen != "desk" {
		t.Fatal("reopening results lost original return screen")
	}
}

func TestResultMenusDoNotRepeatShortcuts(t *testing.T) {
	m := resultScopeFixture()
	m.openProjectResults()
	if strings.Contains(m.resultListHeader(120), "Enter") {
		t.Fatal("list duplicates footer shortcuts")
	}
	next, _ := m.updateProjectResults("enter")
	m = next.(model)
	view := ansi.Strip(m.View())
	if strings.Count(view, "Tab раздел") != 1 || strings.Count(view, "Esc список") != 1 {
		t.Fatalf("duplicate card menu:\n%s", view)
	}
}

func TestSplitFindingListUpdatesDetailsAndFocus(t *testing.T) {
	m := resultScopeFixture()
	m.width, m.height = 120, 32
	m.openProjectResults()
	next, _ := m.updateProjectResults("enter")
	m = next.(model)
	if m.findingDetailFocus {
		t.Fatal("initial focus must allow selecting findings")
	}
	before := m.findingDetail.TemplateID
	next, _ = m.updateProjectResults("down")
	m = next.(model)
	if m.findingIndex != 1 || m.findingDetail.TemplateID == before || m.findingPane != 1 {
		t.Fatal("list selection did not update detail")
	}
	for _, size := range [][2]int{{88, 18}, {100, 24}, {160, 40}} {
		m.width, m.height = size[0], size[1]
		view := m.View()
		if !strings.Contains(ansi.Strip(view), "Найдено") || !strings.Contains(ansi.Strip(view), "Находка 2 /") {
			t.Fatalf("panes missing at %v", size)
		}
		for _, line := range strings.Split(view, "\n") {
			if ansi.StringWidth(line) != m.width {
				t.Fatalf("bad width at %v", size)
			}
		}
	}
	m.findingDetail.Description = strings.Repeat("Long description\n", 50)
	next, _ = m.updateProjectResults("right")
	m = next.(model)
	next, _ = m.updateProjectResults("down")
	m = next.(model)
	if !m.findingDetailFocus || m.findingIndex != 1 || m.findingOffset != 1 {
		t.Fatal("right panel must scroll without changing selection")
	}
	next, _ = m.updateProjectResults("left")
	m = next.(model)
	if m.screen != "project-results" || m.findingDetailFocus || m.findingPane != 1 {
		t.Fatal("left must focus list without closing details")
	}
	next, _ = m.updateProjectResults("up")
	m = next.(model)
	if m.findingIndex != 0 || m.findingOffset != 0 {
		t.Fatal("new selection must reset detail scroll")
	}
}
