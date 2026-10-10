package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"strings"
)

const (
	globalSettingLibrary = iota
	globalSettingDependencies
)

var globalSettingLabels = []string{"Библиотека шаблонов", "Зависимости: Python и Ruby"}

func (m model) updateGlobalSettings(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.screen = "projects"
	case "up", "k":
		m.globalSettingsIndex = max(0, m.globalSettingsIndex-1)
	case "down", "j":
		m.globalSettingsIndex = min(len(globalSettingLabels)-1, m.globalSettingsIndex+1)
	case "enter", " ":
		if m.globalSettingsIndex == globalSettingLibrary {
			return m.openLibrarySettings()
		}
		return m.openDependencySettings()
	}
	return m, nil
}

func (m model) viewGlobalSettings(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("Общие настройки wscan") + "\n\n")
	body.WriteString("Библиотека и зависимости используются всеми проектами.\n\n")
	for i, label := range globalSettingLabels {
		body.WriteString(renderListRow(label+" — открыть", i == m.globalSettingsIndex, w-4))
	}
	body.WriteString("\nПараметры сканирования настраиваются внутри проекта.\n\n↑/↓ — выбрать · Enter — открыть · Esc — проекты\n")
	return m.renderPanel(w, body.String())
}
