package tui

import (
	"context"
	"strings"
	"testing"
	"wscan/internal/domain"
	"wscan/internal/libsync"
)

func TestCommonSettingsBeforeAnyProject(t *testing.T) {
	m := model{screen: "projects", ctx: context.Background(), appDir: t.TempDir()}
	if !strings.Contains(m.viewProjects(100), "Общие настройки") {
		t.Fatal("initial screen does not advertise common settings")
	}
	next, cmd := m.updateProjects("p")
	m = next.(model)
	if m.screen != "global-settings" || cmd != nil || m.current.ID != 0 {
		t.Fatal("common settings required a project")
	}
	next, cmd = m.updateGlobalSettings("enter")
	m = next.(model)
	if m.screen != "library-settings" || cmd == nil {
		t.Fatal("common library not opened")
	}
	next, _ = m.updateLibrarySettings("esc")
	m = next.(model)
	if m.screen != "global-settings" {
		t.Fatal("library did not return to common settings")
	}
	next, _ = m.updateGlobalSettings("down")
	m = next.(model)
	next, cmd = m.updateGlobalSettings("enter")
	m = next.(model)
	if m.screen != "dependency-settings" || cmd == nil {
		t.Fatal("common dependencies not opened")
	}
	next, _ = m.updateDependencySettings("esc")
	m = next.(model)
	next, cmd = m.updateGlobalSettings("esc")
	if next.(model).screen != "projects" || cmd != nil {
		t.Fatal("common settings back must return to projects")
	}
}

func TestProjectSettingsAreSeparateAndPersistOnlyCurrentProject(t *testing.T) {
	m := newTestModelForSettings(t)
	otherID, err := m.store.CreateProject(m.ctx, "other-project")
	if err != nil {
		t.Fatal(err)
	}
	before, err := m.store.ListProjects(m.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var otherBefore domain.Project
	for _, p := range before {
		if p.ID == otherID {
			otherBefore = p
		}
	}
	if len(settingLabels) != 16 {
		t.Fatal("common settings leaked into project menu")
	}
	for _, row := range m.settingRows() {
		if strings.Contains(row, "Библиотека") || strings.Contains(row, "Зависимости:") {
			t.Fatal("common settings in project rows")
		}
	}
	m.settingsIndex = 0
	next, _ := m.saveSettingValue("17")
	m = next.(model)
	after, err := m.store.ListProjects(m.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range after {
		if p.ID == m.current.ID && p.RPS != 17 {
			t.Fatal("current project not updated")
		}
		if p.ID == otherID && (p.RPS != otherBefore.RPS || p.AllowCodeExec != otherBefore.AllowCodeExec) {
			t.Fatal("other project changed")
		}
	}
	if !strings.Contains(m.viewSettings(100), m.current.Name) {
		t.Fatal("project title lacks its name")
	}
	next, _ = m.updateSettings("esc")
	if next.(model).screen != "desk" {
		t.Fatal("project settings back did not return to project")
	}
}

func TestCommonDownloadedCatalogCannotModifyProjectSelections(t *testing.T) {
	m := model{libraryStatus: libsync.Status{Installed: true}, screen: "library-settings", current: domain.Project{ID: 7, TemplateIDs: []string{"example.yaml"}}}
	next, _ := m.updateLibrarySettings("t")
	m = next.(model)
	if !m.catalogReadOnly || len(m.selectedSet()) != 0 {
		t.Fatal("common catalog exposes project selection")
	}
	for _, key := range []string{" ", "space", "A", "x"} {
		next, cmd := m.updateCatalogGroups(key)
		if cmd != nil || len(next.(model).current.TemplateIDs) != 1 {
			t.Fatal("common group selection mutated a project")
		}
	}
	for _, key := range []string{"enter", " ", "space", "A", "x"} {
		_, cmd := m.updateCatalog(key)
		if cmd != nil {
			t.Fatal("common catalog allowed editing")
		}
	}
	m.openCatalog(false, "desk")
	if m.catalogReadOnly || len(m.selectedSet()) != 1 {
		t.Fatal("project catalog did not restore editing")
	}
}
