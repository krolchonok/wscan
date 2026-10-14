package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

var sidebarOrder = []int{11, 10, 12, 0, 1, 2, 4, 5, 6, 7, 8, 3, 9}

// Display and dispatch share stable shortcuts across project screens.
var sidebarShortcuts = []struct {
	key    string
	action int
}{
	{"1", 10}, {"2", 0}, {"3", 1}, {"4", 2}, {"5", 4},
	{"6", 5}, {"7", 6}, {"8", 7}, {"9", 8}, {"0", 9},
	{"f", 3}, {"b", 11}, {"p", 12},
}

func sidebarShortcutKey(action int) string {
	for _, item := range sidebarShortcuts {
		if item.action == action {
			return item.key
		}
	}
	return ""
}

func (m model) selectSidebarShortcut(key string) (tea.Model, tea.Cmd, bool) {
	if !m.hasSidebar() {
		return m, nil, false
	}
	// A content pane keeps its own filter key; focusing the menu selects its filter.
	if key == "f" && !m.reconMenuFocus && m.screen != "recon" {
		return m, nil, false
	}
	for _, item := range sidebarShortcuts {
		if item.key == key {
			visible := false
			for _, index := range m.sidebarItems() {
				if index == item.action {
					visible = true
					break
				}
			}
			if !visible {
				return m, nil, false
			}
			m.reconMenuIndex = item.action
			m.reconMenuFocus = false
			next, cmd := m.runReconAction()
			return next, cmd, true
		}
	}
	return m, nil, false
}

func (m model) hasSidebar() bool {
	if m.current.ID <= 0 || m.resultDeleteConfirm || (!m.sidebarEnabled && m.screen != "recon" && m.screen != "recon-host-menu") {
		return false
	}
	switch m.screen {
	case "checks-menu", "ad-menu", "recon", "recon-host-menu", "desk", "port-browser", "networks", "guided-scan", "credentials", "settings", "jobs", "job-details", "project-results", "history", "interaction-menu", "action-menu":
		return true
	}
	return false
}

func sidebarWidth(width int) int { return min(26, max(22, width/4)) }

func (m model) sidebarItems() []int {
	if m.screen != "recon" && m.screen != "desk" {
		return sidebarOrder
	}
	var items []int
	for _, index := range sidebarOrder {
		if index != 11 {
			items = append(items, index)
		}
	}
	return items
}

func (m model) viewSidebar(width int) string {
	items := m.sidebarItems()
	var body strings.Builder
	body.WriteString(headingStyle.Render("Проект") + "\n")
	pivot := 0
	for i, index := range items {
		if index == m.reconMenuIndex {
			pivot = i
		}
	}
	lo, hi := windowRange(pivot, len(items), max(1, m.bodyHeight()-5))
	body.WriteString(moreLine(lo, true))
	for _, index := range items[lo:hi] {
		label := reconActions[index]
		if index == 3 && m.sidebarEnabled {
			label = "Выбор машин"
		}
		if index == 11 && m.screen == "recon-host-menu" {
			label = "← Все машины"
		}
		if key := sidebarShortcutKey(index); key != "" {
			label = key + " " + label
		}
		body.WriteString(renderListRow(label, m.reconMenuFocus && index == m.reconMenuIndex, width))
	}
	body.WriteString(moreLine(len(items)-hi, false))
	return renderColumn(body.String(), width-4, m.bodyHeight()-2, m.reconMenuFocus)
}

func (m model) updateSidebar(key string) (tea.Model, tea.Cmd, bool) {
	if m.screen == "port-browser" {
		switch key {
		case "left", "shift+tab":
			if !m.reconMenuFocus && m.portBrowserFocus > 0 {
				m.portBrowserFocus--
			} else if key == "shift+tab" && m.reconMenuFocus {
				m.reconMenuFocus = false
				m.portBrowserFocus = 1
			} else {
				m.reconMenuFocus = true
			}
			return m, nil, true
		case "right", "tab":
			if m.reconMenuFocus {
				m.reconMenuFocus = false
				m.portBrowserFocus = 0
			} else if key == "tab" && m.portBrowserFocus == 1 {
				m.reconMenuFocus = true
			} else {
				m.portBrowserFocus = 1
			}
			return m, nil, true
		}
	}
	if m.screen == "job-details" && !m.reconMenuFocus && (key == "left" || key == "right") {
		next, cmd := m.updateJobDetails(key)
		return next, cmd, true
	}
	if m.screen == "desk" {
		switch key {
		case "left", "shift+tab":
			if !m.reconMenuFocus && m.focusCol > 0 {
				next, cmd := m.updateDesk("left")
				return next, cmd, true
			}
			if key == "shift+tab" && m.reconMenuFocus {
				m.reconMenuFocus = false
				m.focusCol = 2
			} else {
				m.reconMenuFocus = true
			}
			return m, nil, true
		case "right", "tab":
			if m.reconMenuFocus {
				m.reconMenuFocus = false
				m.focusCol = 0
				return m, nil, true
			}
			if key == "tab" && m.focusCol == 2 {
				m.reconMenuFocus = true
				return m, nil, true
			}
			next, cmd := m.updateDesk("right")
			return next, cmd, true
		}
	}
	if key == "left" {
		m.reconMenuFocus = true
		return m, nil, true
	}
	if key == "right" {
		m.reconMenuFocus = false
		return m, nil, true
	}
	if key == "tab" || key == "shift+tab" {
		m.reconMenuFocus = !m.reconMenuFocus
		return m, nil, true
	}
	if !m.reconMenuFocus {
		return m, nil, false
	}
	switch key {
	case "up", "down":
		items := m.sidebarItems()
		pos := 0
		for i, index := range items {
			if index == m.reconMenuIndex {
				pos = i
			}
		}
		if key == "up" {
			pos = (pos + len(items) - 1) % len(items)
		} else {
			pos = (pos + 1) % len(items)
		}
		m.reconMenuIndex = items[pos]
	case "enter":
		m.reconMenuFocus = false
		next, cmd := m.runReconAction()
		return next, cmd, true
	}
	return m, nil, true
}

func (m model) sidebarBack() (tea.Model, tea.Cmd) {
	switch m.screen {
	case "recon", "desk":
		m.screen = "projects"
	case "checks-menu", "ad-menu":
		m.screen = "desk"
	case "recon-host-menu":
		m.screen = "recon"
	case "guided-scan":
		return m.updateGuidedScan("esc")
	case "action-menu":
		m.screen = "desk"
	default:
		// Use the existing screen return path, including any save/cleanup logic.
		return m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	}
	return m, nil
}

func (m model) workspaceFooter() string {
	if m.screen == "port-browser" && !m.reconMenuFocus {
		return m.footer()
	}
	if m.screen == "job-details" && !m.reconMenuFocus {
		return "←→ итог/ошибки/журнал · ↑↓ прокрутка · Enter результаты · Tab меню"
	}
	if m.screen == "desk" && m.hasSidebar() {
		return "←→ колонки · ↑↓ выбор · Enter действие · Tab меню"
	}
	if m.screen == "recon" {
		return "←→ панели · ↑↓ выбор · Enter действие · Tab меню"
	}
	if m.hasSidebar() {
		return "← меню · → содержимое · ↑↓ выбор · Enter открыть"
	}
	return m.footer() + "   ·   ? помощь"
}
