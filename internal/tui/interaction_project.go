package tui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"sort"
)

const interactionMenuCount = 17
const interactionADScanIndex = 14

func (m *model) openProjectInteractions() {
	previous := m.screen
	m.openInteractionMenu()
	m.interactionReturn = previous
	m.interactionIndex = interactionADScanIndex // Project inventory setup stays visible on entry.
}
func (m model) interactionHosts() []string {
	hosts := make([]string, 0, len(m.inventory))
	for host := range m.inventory {
		hosts = append(hosts, host)
	}
	for _, host := range m.hostOrder {
		found := false
		for _, current := range hosts {
			if current == host {
				found = true
				break
			}
		}
		if !found {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return hosts
}
func (m model) updateInteractionTargets(key string) (tea.Model, tea.Cmd) {
	hosts := m.interactionHosts()
	switch key {
	case "esc", "q":
		m.screen = "interaction-menu"
	case "up", "k":
		m.interactionHostIndex = max(0, m.interactionHostIndex-1)
	case "down", "j":
		m.interactionHostIndex = min(max(0, len(hosts)-1), m.interactionHostIndex+1)
	case "enter":
		if len(hosts) == 0 {
			m.message = "Добавь хост в меню «Хосты»"
			return m, nil
		}
		host := hosts[min(m.interactionHostIndex, len(hosts)-1)]
		m.openHostScope("")
		m.selectHost(host)
		m.focusCol = 0
		m.serviceIndex = 0
		previous := m.interactionReturn
		m.openInteractionMenu()
		m.interactionReturn = previous
	}
	return m, nil
}
func (m model) viewInteractionTargets(w int) string {
	hosts := m.interactionHosts()
	body := headingStyle.Render("Взаимодействие — выбор хоста") + fmt.Sprintf("\n\nПроект: %s\n↑/↓ выбрать · Enter открыть · Esc назад\n", m.current.Name)
	lo, hi := windowRange(m.interactionHostIndex, len(hosts), max(1, m.panelRows()-5))
	for i := lo; i < hi; i++ {
		body += renderListRow(smbDisplayName(hosts[i]), i == m.interactionHostIndex, w)
	}
	if len(hosts) == 0 {
		body += "\nНет хостов. Добавь их в меню «2 Хосты».\nДля веба можно указать URL вручную."
	}
	return m.renderPanel(w, body)
}
