package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

var hostSelectionLabels = []string{"Все в списке", "Все живые", "Все с открытым портом…", "Очистить выбор"}

func (m model) viewHostSelection(width int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("Выбрать хосты") + "\n\n")
	for i, label := range hostSelectionLabels {
		body.WriteString(renderListRow(label, i == m.actionIndex, width))
	}
	body.WriteString("\nПо результатам обнаружения в текущем списке.\nЖивые: сохранённые открытые порты или ответы в этой сессии.\nПорт без протокола означает TCP.")
	return m.renderPanel(width, body.String())
}

func (m model) updateHostSelection(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.screen = "desk"
	case "up", "k":
		m.actionIndex = max(0, m.actionIndex-1)
	case "down", "j":
		m.actionIndex = min(len(hostSelectionLabels)-1, m.actionIndex+1)
	case "enter":
		m.screen = "desk"
		switch m.actionIndex {
		case 0:
			m.selectMatchingHosts("all", 0, "")
		case 1:
			m.selectMatchingHosts("alive", 0, "")
		case 2:
			m.actionIndex = 0
			m.screen = "host-port-selection"
		case 3:
			m.selectedHosts = nil
			m.message = "Выбор очищен"
		}
	}
	return m, nil
}

type hostPortChoice struct {
	port     int
	protocol string
	hosts    int
}

func (m model) hostPortChoices() []hostPortChoice {
	type endpoint struct {
		port     int
		protocol string
	}
	counts := map[endpoint]int{}
	for _, host := range m.hostOrder {
		seen := map[endpoint]bool{}
		for _, service := range m.servicesFor(host) {
			state := strings.ToLower(service.State)
			if service.Port < 1 || service.Port > 65535 || state != "" && state != "open" {
				continue
			}
			protocol := strings.ToLower(service.Protocol)
			if protocol == "" {
				protocol = "tcp"
			}
			if protocol != "tcp" && protocol != "udp" {
				continue
			}
			key := endpoint{service.Port, protocol}
			if !seen[key] {
				counts[key]++
				seen[key] = true
			}
		}
	}
	choices := make([]hostPortChoice, 0, len(counts))
	for key, count := range counts {
		choices = append(choices, hostPortChoice{key.port, key.protocol, count})
	}
	sort.Slice(choices, func(i, j int) bool {
		if choices[i].port != choices[j].port {
			return choices[i].port < choices[j].port
		}
		return choices[i].protocol < choices[j].protocol
	})
	return choices
}

func (m model) viewHostPortSelection(width int) string {
	choices := m.hostPortChoices()
	var body strings.Builder
	body.WriteString(headingStyle.Render("Выбрать по открытому порту") + "\n\n")
	if len(choices) == 0 {
		body.WriteString("Открытые порты пока не найдены.\n")
	}
	index := min(max(0, m.actionIndex), len(choices))
	lo, hi := windowRange(index, len(choices)+1, max(1, m.bodyHeight()-8))
	body.WriteString(moreLine(lo, true))
	for i := lo; i < hi; i++ {
		label := "Ввести порт вручную…"
		if i < len(choices) {
			choice := choices[i]
			label = fmt.Sprintf("%d/%s · хостов: %d", choice.port, choice.protocol, choice.hosts)
		}
		body.WriteString(renderListRow(label, i == index, width))
	}
	body.WriteString(moreLine(len(choices)+1-hi, false))
	body.WriteString("\nОткрытые порты хостов в текущем списке.")
	return m.renderPanel(width, body.String())
}

func (m model) updateHostPortSelection(key string) (tea.Model, tea.Cmd) {
	choices := m.hostPortChoices()
	m.actionIndex = min(max(0, m.actionIndex), len(choices))
	switch key {
	case "esc", "q":
		m.screen, m.actionIndex = "host-selection", 2
	case "up", "k":
		m.actionIndex = max(0, m.actionIndex-1)
	case "down", "j":
		m.actionIndex = min(len(choices), m.actionIndex+1)
	case "enter":
		if m.actionIndex == len(choices) {
			m.startInput("select-host-port")
		} else {
			choice := choices[m.actionIndex]
			m.screen = "desk"
			m.selectMatchingHosts("port", choice.port, choice.protocol)
		}
	}
	return m, nil
}

func (m *model) selectMatchingHosts(mode string, port int, protocol string) {
	live := map[string]bool{}
	if mode == "alive" {
		for _, j := range m.jobs {
			if j.projectID == m.current.ID && j.kind != jobPTR && j.result != nil {
				for _, host := range j.result.LiveHosts {
					live[host] = true
				}
			}
		}
	}
	selected := map[string]bool{}
	for _, host := range m.hostOrder {
		match := mode == "all" || mode == "alive" && live[host]
		for _, service := range m.servicesFor(host) {
			state := strings.ToLower(service.State)
			if service.Port <= 0 || state != "" && state != "open" {
				continue
			}
			transport := strings.ToLower(service.Protocol)
			if transport == "" {
				transport = "tcp"
			}
			match = match || mode == "alive" || mode == "port" && service.Port == port && transport == protocol
		}
		if match {
			selected[host] = true
		}
	}
	if len(selected) == 0 {
		m.message = "Подходящих хостов нет · прежний выбор сохранён"
		return
	}
	m.selectedHosts = selected
	m.hostIndex, m.focusCol, m.serviceIndex = -1, 0, -1
	m.message = fmt.Sprintf("Выбрано хостов: %d · Enter — действие для выбранных", len(selected))
}
