package tui

import (
	"strings"
	"testing"
	"wscan/internal/dependencies"
)

func TestDependencySettingsOpenAndInstallConfirmation(t *testing.T) {
	m := model{screen: "global-settings", globalSettingsIndex: globalSettingDependencies}
	next, cmd := m.updateGlobalSettings("enter")
	m = next.(model)
	if m.screen != "dependency-settings" || cmd == nil {
		t.Fatal("panel did not open")
	}
	m.dependenciesLoading = false
	m.interpreters = []dependencies.Interpreter{{Name: "Python 3", Path: "/python", Version: "Python 3.12"}, {Name: "Ruby"}}
	next, cmd = m.updateDependencySettings("enter")
	if next.(model).screen != "dependency-settings" || cmd != nil {
		t.Fatal("installed interpreter offered install")
	}
	m.dependencyIndex = 1
	next, cmd = m.updateDependencySettings("enter")
	m = next.(model)
	if cmd != nil {
		t.Fatal("first Enter executed installation")
	}
	// On Linux without sudo the panel reports the missing privilege tool.
	if m.screen != "dependency-install-confirm" && m.dependencyError == "" {
		t.Fatal("no install plan or error shown")
	}
	if m.screen == "dependency-install-confirm" {
		next, cmd = m.updateDependencyInstallConfirm("esc")
		if next.(model).screen != "dependency-settings" || cmd != nil {
			t.Fatal("cancel did not return without installation")
		}
	}
}

func TestDependencyStatusViewAndRefresh(t *testing.T) {
	m := model{interpreters: []dependencies.Interpreter{{Name: "Python 3", Path: "/python", Version: "Python 3.12"}, {Name: "Ruby"}}}
	view := m.viewDependencySettings(100)
	for _, want := range []string{"Python 3.12", "/python", "Ruby", "не установлен"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %s", want)
		}
	}
	next, cmd := m.updateDependencySettings("r")
	if !next.(model).dependenciesLoading || cmd == nil {
		t.Fatal("refresh not started")
	}
	next, cmd = m.updateDependencySettings("esc")
	if next.(model).screen != "global-settings" || cmd != nil {
		t.Fatal("back failed")
	}
}
