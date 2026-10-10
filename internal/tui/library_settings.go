package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/libsync"
)

type libraryStatusDone struct {
	status libsync.Status
	err    error
}

func (m model) inspectLibraryCmd() tea.Cmd {
	appDir := m.appDir
	return func() tea.Msg {
		status, err := libsync.Inspect(appDir)
		return libraryStatusDone{status: status, err: err}
	}
}

func (m model) openLibrarySettings() (tea.Model, tea.Cmd) {
	m.screen = "library-settings"
	m.libraryStatusLoading = true
	return m, m.inspectLibraryCmd()
}

func (m model) updateLibrarySettings(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.screen = "global-settings"
	case "t":
		if !m.libraryStatus.Installed || m.librarySyncing {
			return m, nil
		}
		m.pendingTemplateIDs = nil
		m.openCatalog(false, "library-settings")
		m.catalogReadOnly = true
		if len(m.entries) == 0 {
			return m, m.loadCatalogCmd()
		}
		return m, nil
	case "enter", " ":
		if m.librarySyncing || m.libraryStatusLoading {
			return m, nil
		}
		m.librarySyncing = true
		m.libraryError = ""
		m.message = "Скачиваю шаблоны из GitHub…"
		return m, m.downloadLibraryCmd()
	}
	return m, nil
}

func (m model) viewLibrarySettings(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("Библиотека шаблонов") + "\n\n")
	cfg := m.libraryStatus.Config
	url := cfg.URL
	if url == "" {
		url = libsync.DefaultRepositoryURL
	}
	fmt.Fprintf(&body, "Репозиторий: %s\n", url)
	ref := cfg.Ref
	if ref == "" {
		ref = "main"
	}
	fmt.Fprintf(&body, "Ветка: %s\n\n", ref)
	if m.libraryStatusLoading {
		body.WriteString("Проверяю скачанную библиотеку…\n")
	} else if m.libraryStatus.Installed {
		fmt.Fprintf(&body, "Состояние: скачана\nШаблонов YAML: %d\nФайлов, включая зависимости: %d\nРазмер: %.1f МБ\nПапка: %s\n", m.libraryStatus.Templates, m.libraryStatus.Files, float64(m.libraryStatus.Bytes)/(1024*1024), cfg.Path)
		if cfg.UpdatedAt != "" {
			date := cfg.UpdatedAt
			if parsed, err := time.Parse(time.RFC3339, date); err == nil {
				date = parsed.Local().Format("02.01.2006 15:04")
			}
			fmt.Fprintf(&body, "Обновлено: %s\n", date)
		}
		if cfg.Commit != "" {
			commit := cfg.Commit
			if len(commit) > 12 {
				commit = commit[:12]
			}
			fmt.Fprintf(&body, "Версия: %s\n", commit)
		}
	} else {
		body.WriteString("Состояние: шаблоны ещё не скачаны\n")
	}
	body.WriteString("\n")
	if m.librarySyncing {
		body.WriteString("Скачивание… Интерфейс остаётся доступным.\n")
	} else {
		label := "Скачать шаблоны"
		if m.libraryStatus.Installed {
			label = "Обновить шаблоны"
		}
		body.WriteString(renderListRow("[ "+label+" ]", !m.libraryStatusLoading, w-4))
		body.WriteString("\nEnter — скачать / обновить\n")
		if m.libraryStatus.Installed {
			body.WriteString("t — посмотреть скачанные проверки\n")
		}
	}
	if m.libraryError != "" {
		body.WriteString("\n" + messageStyle.Render("Ошибка: "+m.libraryError) + "\n")
	}
	body.WriteString("\nПриватный GitHub: используется авторизация gh / Git.\nПри отсутствии доступа выполните gh auth login.\nEsc — настройки\n")
	return m.renderPanel(w, body.String())
}
