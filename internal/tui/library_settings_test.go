package tui

import (
	"context"
	"strings"
	"testing"
	"wscan/internal/libsync"
)

func TestLibrarySettingsNavigationAndSingleDownload(t *testing.T) {
	m := model{ctx: context.Background(), appDir: t.TempDir(), globalSettingsIndex: globalSettingLibrary, screen: "global-settings"}
	next, cmd := m.updateGlobalSettings("enter")
	m = next.(model)
	if m.screen != "library-settings" || cmd == nil {
		t.Fatal("settings did not open library")
	}
	next, _ = m.Update(cmd())
	m = next.(model)
	if m.libraryStatusLoading {
		t.Fatal("status remained loading")
	}
	next, cmd = m.updateLibrarySettings("enter")
	m = next.(model)
	if !m.librarySyncing || cmd == nil {
		t.Fatal("download not started")
	}
	_, cmd = m.updateLibrarySettings("enter")
	if cmd != nil {
		t.Fatal("duplicate download started")
	}
	next, _ = m.updateLibrarySettings("esc")
	if next.(model).screen != "global-settings" {
		t.Fatal("back navigation failed")
	}
}

func TestLibrarySettingsInstalledView(t *testing.T) {
	m := model{libraryStatus: libsync.Status{Installed: true, Templates: 42, Files: 45, Bytes: 1024, Config: libsync.Config{URL: libsync.DefaultRepositoryURL, Path: "/tmp/library", Commit: "1234567890123456", UpdatedAt: "2026-10-09T12:00:00Z"}}}
	view := m.viewLibrarySettings(100)
	for _, want := range []string{"скачана", "42", "45", "Обновить шаблоны", "123456789012", "wscan-templates"} {
		if !strings.Contains(view, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestLibrarySettingsInstalledCatalogBack(t *testing.T) {
	m := model{libraryStatus: libsync.Status{Installed: true}, screen: "library-settings"}
	next, _ := m.updateLibrarySettings("t")
	result := next.(model)
	if result.screen != "catalog-groups" || result.catalogBack != "library-settings" {
		t.Fatal("downloaded catalog navigation failed")
	}
}
