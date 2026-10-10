package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/catalog"
	"wscan/internal/domain"
)

func parseSinglePort(value string) (int, string, error) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), "/")
	protocol := "tcp"
	if len(parts) == 2 {
		protocol = parts[1]
	}
	port, err := strconv.Atoi(parts[0])
	if err != nil || port < 1 || port > 65535 || len(parts) > 2 || (protocol != "tcp" && protocol != "udp") {
		return 0, "", fmt.Errorf("укажи один порт: 445, 443/tcp или 53/udp (1–65535)")
	}
	return port, protocol, nil
}

func (m model) bulkPortServices() ([]domain.Service, []string) {
	var services []domain.Service
	var hosts []string
	seen := map[string]bool{}
	for _, host := range m.actionHosts {
		matched := false
		for _, service := range m.servicesFor(host) {
			protocol := strings.ToLower(service.Protocol)
			if protocol == "" {
				protocol = "tcp"
			}
			if service.Port != m.bulkPort || protocol != m.bulkProtocol {
				continue
			}
			matched = true
			key := fmt.Sprintf("%s:%d/%s", service.Host, service.Port, protocol)
			if !seen[key] {
				service.Protocol = protocol
				services = append(services, service)
				seen[key] = true
			}
		}
		if matched {
			hosts = append(hosts, host)
		}
	}
	return services, uniqueStrings(hosts)
}

func (m model) saveBulkPort(value string) (tea.Model, tea.Cmd) {
	port, protocol, err := parseSinglePort(value)
	if err != nil {
		m.startInput("bulk-port")
		m.input = value
		m.message = err.Error()
		return m, nil
	}
	m.bulkPort, m.bulkProtocol = port, protocol
	m.actionService = nil
	services, _ := m.bulkPortServices()
	if len(services) == 0 {
		m.startInput("bulk-port")
		m.input = value
		m.message = fmt.Sprintf("Среди выбранных хостов нет найденного открытого порта %d/%s. Сначала выполни поиск портов.", port, protocol)
		return m, nil
	}
	m.openCatalog(true, "action-menu")
	direction := catalog.ServiceDirection(services[0])
	for i, group := range m.visibleCatalogGroups() {
		if group.Name == direction {
			m.catalogGroupIndex = i
			break
		}
	}
	m.message = fmt.Sprintf("%d/%s: %d подходящих сервисов. Остальные хосты будут пропущены.", port, protocol, len(services))
	return m, nil
}
