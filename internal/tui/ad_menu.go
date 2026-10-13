package tui

import tea "github.com/charmbracelet/bubbletea"

var adMenuActions = []string{"Разведка AD", "Учётки, Kerberos, SYSVOL", "Coerce / Responder", "Контроллер домена: выбрать машину"}

func (m model) viewADMenu(w int) string {
	body := headingStyle.Render("AD") + "\n\n"
	if m.currentHost() != "" {
		body += "Машина: " + m.currentHost() + "\n\n"
	}
	if m.adAccessManualHost != "" {
		body += "Контроллер: " + m.adAccessManualHost + " (вручную)\n\n"
	}
	for i, label := range adMenuActions {
		body += renderListRow(label, i == m.adMenuIndex, w-4)
	}
	return m.renderPanel(w, body)
}
func (m model) updateADMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up":
		m.adMenuIndex = max(0, m.adMenuIndex-1)
	case "down":
		m.adMenuIndex = min(len(adMenuActions)-1, m.adMenuIndex+1)
	case "esc":
		m.screen = "desk"
	case "enter":
		switch m.adMenuIndex {
		case 0:
			m.openGuidedScan()
			m.wizardProfile = 1
			m.wizardStep = 0
			if m.wizardScope != "" {
				m.wizardIndex = 1
			}
		case 1:
			m.openADAccess()
			return m, m.detectADAccessIdentityCmd()
		case 2:
			m.openInteractionMenu()
			m.interactionReturn = "ad-menu"
			m.screen = "ad-menu"
			return m.openHostCoercion()
		case 3:
			m.openADAccess()
			m.screen = "ad-menu"
			m.openADControllerPicker()
		}
	}
	return m, nil
}

// AD operations live in the AD section, not in the service tool menu.
func interactionToolIndices() []int { return []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11} }
func nextInteractionTool(current, delta int) int {
	indices := interactionToolIndices()
	for i, index := range indices {
		if index == current {
			return indices[(i+delta+len(indices))%len(indices)]
		}
	}
	return indices[0]
}
