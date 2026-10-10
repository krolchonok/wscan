package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/dependencies"
)

type dependenciesDone struct{ items []dependencies.Interpreter }
type dependencyInstallDone struct {
	err     error
	browser bool
}

func (m model) inspectDependenciesCmd() tea.Cmd {
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return func() tea.Msg { return dependenciesDone{items: dependencies.Inspect(ctx)} }
}

func (m model) openDependencySettings() (tea.Model, tea.Cmd) {
	m.screen = "dependency-settings"
	m.dependenciesLoading = true
	m.dependencyError = ""
	return m, m.inspectDependenciesCmd()
}

func (m model) updateDependencySettings(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.screen = "global-settings"
	case "up", "k":
		m.dependencyIndex = max(0, m.dependencyIndex-1)
	case "down", "j":
		m.dependencyIndex = min(1, m.dependencyIndex+1)
	case "r":
		if m.dependenciesLoading {
			return m, nil
		}
		m.dependenciesLoading = true
		m.dependencyError = ""
		return m, m.inspectDependenciesCmd()
	case "enter", " ":
		if m.dependenciesLoading || len(m.interpreters) != 2 {
			return m, nil
		}
		if m.interpreters[m.dependencyIndex].Installed() {
			m.message = "Интерпретатор уже установлен"
			return m, nil
		}
		plan, err := dependencies.InstallPlan(m.dependencyIndex)
		if err != nil {
			m.dependencyError = err.Error()
			return m, nil
		}
		m.dependencyPlan = plan
		m.screen = "dependency-install-confirm"
	}
	return m, nil
}

func (m model) updateDependencyInstallConfirm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "n", "q":
		m.screen = "dependency-settings"
	case "enter", "y":
		command, err := m.dependencyPlan.Command()
		if err != nil {
			m.dependencyError = err.Error()
			m.screen = "dependency-settings"
			return m, nil
		}
		m.screen = "dependency-settings"
		m.dependenciesLoading = true
		browser := m.dependencyPlan.URL != ""
		return m, tea.ExecProcess(command, func(err error) tea.Msg { return dependencyInstallDone{err: err, browser: browser} })
	}
	return m, nil
}

func (m model) viewDependencySettings(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("Зависимости: Python и Ruby") + "\n\n")
	if m.dependenciesLoading {
		body.WriteString("Проверяю установленные интерпретаторы…\n\n")
	}
	for i, name := range []string{"Python 3", "Ruby"} {
		status := "проверяется"
		if !m.dependenciesLoading {
			status = "не установлен — Enter: установить / скачать"
		}
		if len(m.interpreters) == 2 && m.interpreters[i].Installed() {
			status = m.interpreters[i].Version
		}
		body.WriteString(renderListRow(name+": "+status, i == m.dependencyIndex, w-4))
		if len(m.interpreters) == 2 {
			if m.interpreters[i].Path != "" {
				fmt.Fprintf(&body, "  %s\n", m.interpreters[i].Path)
			}
			if m.interpreters[i].Error != "" {
				fmt.Fprintf(&body, "  %s\n", m.interpreters[i].Error)
			}
		}
	}
	if m.dependencyError != "" {
		body.WriteString("\n" + messageStyle.Render(m.dependencyError) + "\n")
	}
	body.WriteString("\nPython и Ruby нужны для отдельных code-шаблонов.\nОбычные проверки работают на встроенном движке.\n\n↑/↓ — выбрать · Enter — установить отсутствующий\nr — проверить снова · Esc — настройки\n")
	return m.renderPanel(w, body.String())
}

func (m model) viewDependencyInstallConfirm(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("Установка: "+m.dependencyPlan.Name) + "\n\n")
	if m.dependencyPlan.URL != "" {
		body.WriteString("Откроется официальная страница загрузки:\n" + m.dependencyPlan.URL + "\n\nУстановите интерпретатор, добавьте его в PATH и\nнажмите r для повторной проверки.\n")
	} else {
		body.WriteString("Будет выполнена команда:\n" + m.dependencyPlan.Display() + "\n\nУстановщик откроется в терминале. При запросе sudo\nвведите пароль. После завершения wscan вернётся\nк этой панели и проверит установленную версию.\n")
	}
	body.WriteString("\nEnter — продолжить · Esc — отмена\n")
	return m.renderPanel(w, body.String())
}
