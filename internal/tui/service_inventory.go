package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/domain"
)

type serviceInventoryRow struct {
	host    string
	service domain.Service
}

func (m model) serviceInventoryRows() []serviceInventoryRow {
	var rows []serviceInventoryRow
	hosts := m.hostOrder
	if m.serviceInventoryProject {
		hosts = make([]string, 0, len(m.inventory))
		for host := range m.inventory {
			hosts = append(hosts, host)
		}
	}
	for _, host := range hosts {
		for _, service := range m.servicesFor(host) {
			rows = append(rows, serviceInventoryRow{host: host, service: service})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.host != b.host {
			return hostOrderLess(a.host, b.host)
		}
		if a.service.Port != b.service.Port {
			return a.service.Port < b.service.Port
		}
		return strings.ToLower(a.service.Protocol) < strings.ToLower(b.service.Protocol)
	})
	return rows
}

func filterServiceInventory(rows []serviceInventoryRow, query string) []serviceInventoryRow {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return rows
	}
	filtered := make([]serviceInventoryRow, 0, len(rows))
	for _, row := range rows {
		s := row.service
		fields := []string{
			row.host, s.Host, s.Protocol, fmt.Sprint(s.Port), s.Name,
			s.PortService, s.Product, s.Version, s.Tunnel,
		}
		for _, field := range fields {
			if strings.Contains(strings.ToLower(field), query) {
				filtered = append(filtered, row)
				break
			}
		}
	}
	return filtered
}

func (m model) updateServiceInventory(key string) (tea.Model, tea.Cmd) {
	if m.serviceInventoryEditing {
		switch key {
		case "esc":
			m.serviceInventoryEditing = false
		case "enter":
			m.serviceInventoryEditing = false
			m.serviceInventoryIndex = 0
		case "backspace", "ctrl+h":
			runes := []rune(m.serviceInventoryFilter)
			if len(runes) > 0 {
				m.serviceInventoryFilter = string(runes[:len(runes)-1])
			}
			m.serviceInventoryIndex = 0
		case "space":
			m.serviceInventoryFilter += " "
			m.serviceInventoryIndex = 0
		default:
			if len([]rune(key)) == 1 {
				m.serviceInventoryFilter += key
				m.serviceInventoryIndex = 0
			}
		}
		return m, nil
	}
	rows := filterServiceInventory(m.serviceInventoryRows(), m.serviceInventoryFilter)
	switch key {
	case "esc", "q":
		if m.serviceInventoryProject {
			m.screen = "project-results"
			m.serviceInventoryProject = false
			m.refreshProjectResultSelection()
		} else {
			m.screen = "desk"
		}
		m.serviceInventorySelected = nil
	case "/", "f":
		m.serviceInventoryEditing = true
	case "up", "k":
		if m.serviceInventoryIndex > 0 {
			m.serviceInventoryIndex--
		}
	case "down", "j":
		if m.serviceInventoryIndex+1 < len(rows) {
			m.serviceInventoryIndex++
		}
	case "home":
		m.serviceInventoryIndex = 0
	case "end":
		m.serviceInventoryIndex = max(0, len(rows)-1)
	case "x":
		m.serviceInventorySelected = nil
		m.message = "Выбор хостов очищен"
	case "a":
		m.serviceInventorySelected = map[string]bool{}
		for _, row := range rows {
			m.serviceInventorySelected[row.host] = true
		}
		m.message = fmt.Sprintf("Выбрано хостов: %d", len(m.serviceInventorySelected))
	case " ", "space":
		if m.serviceInventoryIndex >= 0 && m.serviceInventoryIndex < len(rows) {
			host := rows[m.serviceInventoryIndex].host
			if m.serviceInventorySelected == nil {
				m.serviceInventorySelected = map[string]bool{}
			}
			if m.serviceInventorySelected[host] {
				delete(m.serviceInventorySelected, host)
			} else {
				m.serviceInventorySelected[host] = true
			}
		}
	case "enter":
		if len(m.serviceInventorySelected) > 0 {
			m.bulkPort, m.bulkProtocol = 0, ""
			for _, row := range rows {
				if !m.serviceInventorySelected[row.host] {
					continue
				}
				protocol := strings.ToLower(row.service.Protocol)
				if protocol == "" {
					protocol = "tcp"
				}
				if m.bulkPort == 0 {
					m.bulkPort, m.bulkProtocol = row.service.Port, protocol
				} else if m.bulkPort != row.service.Port || m.bulkProtocol != protocol {
					m.bulkPort, m.bulkProtocol = 0, ""
					break
				}
			}
			m.actionHosts = make([]string, 0, len(m.serviceInventorySelected))
			hosts := m.hostOrder
			if m.serviceInventoryProject {
				hosts = make([]string, 0, len(m.serviceInventorySelected))
				for host := range m.serviceInventorySelected {
					hosts = append(hosts, host)
				}
				sort.Strings(hosts)
			}
			for _, host := range hosts {
				if m.serviceInventorySelected[host] {
					m.actionHosts = append(m.actionHosts, host)
				}
			}
			m.actionService = nil
		} else if m.serviceInventoryIndex >= 0 && m.serviceInventoryIndex < len(rows) {
			m.bulkPort, m.bulkProtocol = 0, ""
			row := rows[m.serviceInventoryIndex]
			service := row.service
			m.actionService = &service
			m.actionHosts = []string{row.host}
		} else {
			return m, nil
		}
		m.actionIndex = 0
		m.actionReturn = "service-inventory"
		m.pendingTemplateIDs = nil
		m.screen = "action-menu"
		m.serviceInventorySelected = nil
	}
	return m, nil
}

func (m model) viewServiceInventory(width, height int) string {
	rows := filterServiceInventory(m.serviceInventoryRows(), m.serviceInventoryFilter)
	var body strings.Builder
	body.WriteString(headingStyle.Render(fmt.Sprintf("ИНВЕНТАРЬ СЕРВИСОВ (%d/%d)", len(rows), len(m.serviceInventoryRows()))) + "\n")
	filter := m.serviceInventoryFilter
	if m.serviceInventoryEditing {
		filter += "▏"
	}
	if m.serviceInventoryProject {
		body.WriteString("Все хосты и сети текущего проекта · Esc к результатам\n")
	}
	body.WriteString("Фильтр: " + filter + "\n")
	if len(rows) == 0 {
		body.WriteString(mutedStyle.Render("Нет совпадений. Нажми / или f, чтобы изменить фильтр.") + "\n")
		return m.renderPanel(width, body.String())
	}
	visible := max(1, height-5)
	lo, hi := windowRange(m.serviceInventoryIndex, len(rows), visible)
	body.WriteString(moreLine(lo, true))
	for i := lo; i < hi; i++ {
		row := rows[i]
		mark := "[ ] "
		if m.serviceInventorySelected[row.host] {
			mark = "[x] "
		}
		line := fmt.Sprintf("%-18s %s", row.host, serviceLabel(row.service))
		if row.service.Product != "" || row.service.Version != "" {
			line += " · " + strings.TrimSpace(row.service.Product+" "+row.service.Version)
		}
		body.WriteString(renderListRow(mark+line, i == m.serviceInventoryIndex, width-4))
	}
	body.WriteString(moreLine(len(rows)-hi, false))
	return m.renderPanel(width, body.String())
}
