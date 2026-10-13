package tui

import tea "github.com/charmbracelet/bubbletea"

var checksMenuActions = []string{"Выбрать проверки проекта", "CVE по сохранённым версиям", "NSE vuln"}

func (m model) viewChecksMenu(w int) string {
	body := headingStyle.Render("Проверки проекта") + "\n\n"
	for i, label := range checksMenuActions {
		body += renderListRow(label, i == m.checkMenuIndex, w-4)
	}
	return m.renderPanel(w, body)
}
func (m model) updateChecksMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up":
		m.checkMenuIndex = max(0, m.checkMenuIndex-1)
	case "down":
		m.checkMenuIndex = min(len(checksMenuActions)-1, m.checkMenuIndex+1)
	case "esc":
		m.screen = "desk"
	case "enter":
		switch m.checkMenuIndex {
		case 0:
			m.pendingTemplateIDs = nil
			m.openCatalog(false, "checks-menu")
		case 1:
			return m.openVersionCVE()
		case 2:
			return m.openNSEVuln()
		}
	}
	return m, nil
}
