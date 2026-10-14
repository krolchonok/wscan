package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
)

type projectPort struct {
	port     int
	protocol string
	hosts    []portHostRow
}

type portHostRow struct {
	host     string
	services []serviceInventoryRow // Keep every inventory alias for result lookup.
}

type portResultReturn struct {
	scope        resultScope
	returnScreen string
	filter       string
	search       string
	index        int
}

func (m model) projectPorts() []projectPort {
	type key struct {
		port     int
		protocol string
	}
	groups := map[key]map[string]*portHostRow{}
	for _, bucket := range m.hostBuckets() {
		for _, service := range m.servicesFor(bucket) {
			state := strings.ToLower(service.State)
			if service.Port < 1 || service.Port > 65535 || state != "" && state != "open" {
				continue
			}
			service.Protocol = strings.ToLower(service.Protocol)
			if service.Protocol == "" {
				service.Protocol = "tcp"
			}
			if service.Protocol != "tcp" && service.Protocol != "udp" {
				continue
			}
			k := key{service.Port, service.Protocol}
			if groups[k] == nil {
				groups[k] = map[string]*portHostRow{}
			}
			host := service.Host
			if host == "" {
				host = bucket
			}
			identity := strings.ToLower(host)
			if groups[k][identity] == nil {
				groups[k][identity] = &portHostRow{host: host}
			}
			row := groups[k][identity]
			row.services = append(row.services, serviceInventoryRow{host: bucket, service: service})
		}
	}
	var ports []projectPort
	for k, hosts := range groups {
		group := projectPort{port: k.port, protocol: k.protocol}
		for _, row := range hosts {
			group.hosts = append(group.hosts, *row)
		}
		sort.Slice(group.hosts, func(i, j int) bool { return hostOrderLess(group.hosts[i].host, group.hosts[j].host) })
		ports = append(ports, group)
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].port != ports[j].port {
			return ports[i].port < ports[j].port
		}
		return ports[i].protocol < ports[j].protocol
	})
	return ports
}

func (m model) portHostFindings(row portHostRow) []domain.Finding {
	var findings []domain.Finding
	for _, source := range row.services {
		for _, f := range m.rawFindingsForService(source.host, source.service) {
			_, _, scheme, _ := findingEndpoint(f.MatchedAt)
			transport := strings.ToLower(f.Protocol)
			if transport == "udp" || scheme == "udp" {
				if source.service.Protocol != "udp" {
					continue
				}
			} else if transport == "tcp" || scheme == "tcp" || scheme == "http" || scheme == "https" {
				if source.service.Protocol != "tcp" {
					continue
				}
			}
			findings = append(findings, f)
		}
	}
	return orderedResults(findings)
}

func (m model) portScopedFindings(scope resultScope) []domain.Finding {
	var findings []domain.Finding
	for _, group := range m.projectPorts() {
		if group.port != scope.port || group.protocol != scope.protocol {
			continue
		}
		for _, row := range group.hosts {
			if scope.host == "" || scope.host == row.host {
				findings = append(findings, m.portHostFindings(row)...)
			}
		}
	}
	return orderedResults(findings)
}

func (m model) filteredProjectPorts() []projectPort {
	ports := m.projectPorts()
	query := strings.ToLower(strings.TrimSpace(m.portBrowserFilter))
	if query == "" {
		return ports
	}
	var filtered []projectPort
	parts := strings.Split(query, "/")
	number, numberErr := strconv.Atoi(parts[0])
	for _, group := range ports {
		if numberErr == nil && len(parts) <= 2 {
			if group.port == number && (len(parts) == 1 || group.protocol == parts[1]) {
				filtered = append(filtered, group)
			}
			continue
		}
		text := fmt.Sprintf("%d/%s", group.port, group.protocol)
		for _, row := range group.hosts {
			for _, source := range row.services {
				text += " " + source.service.Name + " " + source.service.PortService + " " + source.service.Product
			}
		}
		if strings.Contains(strings.ToLower(text), query) {
			filtered = append(filtered, group)
		}
	}
	return filtered
}

func (m model) selectedProjectPort(ports []projectPort) int {
	for i, group := range ports {
		if group.port == m.portBrowserPort && group.protocol == m.portBrowserProtocol {
			return i
		}
	}
	return 0
}

func (m model) selectedPortHost(group projectPort) int {
	for i, row := range group.hosts {
		if row.host == m.portBrowserHost {
			return i
		}
	}
	return 0
}

func (m *model) openPortBrowser() {
	if m.screen != "port-browser" {
		m.portBrowserReturn = m.screen
		m.portBrowserResultsReturn = nil
		if m.screen == "project-results" {
			m.portBrowserResultsReturn = &portResultReturn{scope: m.resultsScope, returnScreen: m.projectResultsReturn,
				filter: m.projectResultsFilter, search: m.projectResultsSearch, index: m.findingIndex}
		}
	}
	m.screen, m.message = "port-browser", ""
	m.reconMenuIndex = 12
	m.reconMenuFocus = false
	m.portBrowserFocus = 0
	m.portBrowserFilter, m.portBrowserHost = "", ""
	m.portBrowserPort, m.portBrowserProtocol = 0, ""
	if ports := m.projectPorts(); len(ports) > 0 {
		m.portBrowserPort, m.portBrowserProtocol = ports[0].port, ports[0].protocol
		m.portBrowserHost = ports[0].hosts[0].host
	}
}

func (m model) updatePortBrowser(key string) (tea.Model, tea.Cmd) {
	ports := m.filteredProjectPorts()
	switch key {
	case "esc", "q":
		m.screen = m.portBrowserReturn
		if m.screen == "" || m.screen == "port-browser" {
			m.screen = "desk"
		}
		if m.screen == "project-results" && m.portBrowserResultsReturn != nil {
			saved := m.portBrowserResultsReturn
			m.resultsScope, m.projectResultsReturn = saved.scope, saved.returnScreen
			m.projectResultsFilter, m.projectResultsSearch = saved.filter, saved.search
			m.findingIndex, m.findingPane, m.findingOffset = saved.index, 0, 0
			m.findingRaw, m.findingDirectReturn = false, false
			m.projectResultsSelected = nil
			m.refreshProjectResultSelection()
		}
	case "/":
		m.startInput("port-browser-filter")
		m.input = m.portBrowserFilter
	case "left", "shift+tab":
		m.portBrowserFocus = 0
	case "right", "tab":
		m.portBrowserFocus = 1
	default:
		if len(ports) == 0 {
			return m, nil
		}
		index := m.selectedProjectPort(ports)
		group := ports[index]
		hostIndex := m.selectedPortHost(group)
		if key == "up" || key == "k" || key == "down" || key == "j" || key == "home" || key == "end" {
			cursor, length := index, len(ports)
			if m.portBrowserFocus == 1 {
				cursor, length = hostIndex, len(group.hosts)
			}
			switch key {
			case "up", "k":
				cursor--
			case "down", "j":
				cursor++
			case "home":
				cursor = 0
			case "end":
				cursor = length - 1
			}
			cursor = min(max(0, cursor), length-1)
			if m.portBrowserFocus == 0 {
				m.portBrowserPort, m.portBrowserProtocol = ports[cursor].port, ports[cursor].protocol
				m.portBrowserHost = ports[cursor].hosts[0].host
			} else {
				m.portBrowserHost = group.hosts[cursor].host
			}
		} else if key == "enter" && m.portBrowserFocus == 0 {
			m.portBrowserPort, m.portBrowserProtocol = group.port, group.protocol
			m.portBrowserFocus = 1
		} else if key == "enter" || key == "r" {
			scope := resultScope{port: group.port, protocol: group.protocol}
			if key == "enter" {
				scope.host = group.hosts[hostIndex].host
				m.portBrowserHost = scope.host
			}
			m.openScopedResults(scope)
			m.projectResultsFilter = "all"
			m.refreshProjectResultSelection()
		} else if key == "h" {
			row := group.hosts[hostIndex].services[0]
			m.openHostScope("")
			m.selectHost(row.host)
			m.preferredPort, m.preferredProtocol = group.port, group.protocol
			m.serviceIndex = 0
			for i, service := range m.servicesFor(row.host) {
				protocol := strings.ToLower(service.Protocol)
				if protocol == "" {
					protocol = "tcp"
				}
				if service.Port == group.port && protocol == group.protocol {
					m.serviceIndex = i
					break
				}
			}
			m.focusCol = 1
		}
	}
	return m, nil
}

func (m model) viewPortBrowser(width int) string {
	height := m.bodyHeight()
	ports := m.filteredProjectPorts()
	index := m.selectedProjectPort(ports)
	listWidth := width
	split := width >= 88 && height >= 12
	if split {
		listWidth = min(40, max(28, width/3))
	}
	portPane := func(w int) string {
		var b strings.Builder
		b.WriteString(headingStyle.Render(fmt.Sprintf("ПОРТЫ · %d", len(ports))) + "\n")
		b.WriteString(ansi.Truncate("Поиск: "+m.portBrowserFilter, w-4, "…") + "\n")
		if len(ports) == 0 {
			b.WriteString("Открытые порты не найдены.\nЗапустите поиск портов или измените фильтр.")
		} else {
			lo, hi := windowRange(index, len(ports), max(1, height-6))
			b.WriteString(moreLine(lo, true))
			for i := lo; i < hi; i++ {
				group := ports[i]
				label := fmt.Sprintf("%d/%s · хостов: %d", group.port, group.protocol, len(group.hosts))
				b.WriteString(renderListRow(label, i == index, w))
			}
			b.WriteString(moreLine(len(ports)-hi, false))
		}
		return renderColumn(b.String(), w-4, height-2, m.portBrowserFocus == 0 && !m.reconMenuFocus)
	}
	hostPane := func(w int) string {
		var b strings.Builder
		if len(ports) == 0 {
			b.WriteString("ХОСТЫ\nВыберите порт слева.")
		} else {
			group := ports[index]
			hostIndex := m.selectedPortHost(group)
			b.WriteString(headingStyle.Render(fmt.Sprintf("%d/%s · ХОСТЫ: %d", group.port, group.protocol, len(group.hosts))) + "\n")
			b.WriteString(ansi.Truncate("Все сети проекта · открытые порты", w-4, "…") + "\n")
			lo, hi := windowRange(hostIndex, len(group.hosts), max(1, height-8))
			b.WriteString(moreLine(lo, true))
			for i := lo; i < hi; i++ {
				row := group.hosts[i]
				s := row.services[0].service
				label := row.host
				if detail := strings.TrimSpace(s.Name + " " + s.Product + " " + s.Version); detail != "" {
					label += " · " + detail
				}
				b.WriteString(renderListRow(label, i == hostIndex, w))
			}
			b.WriteString(moreLine(len(group.hosts)-hi, false))
			b.WriteString("\n" + ansi.Truncate(resultCounts(groupedProjectResults(m.portHostFindings(group.hosts[hostIndex]))), w-4, "…") + "\n")
			b.WriteString(ansi.Truncate("Enter — результаты хоста · r — всех хостов", w-4, "…"))
		}
		return renderColumn(b.String(), w-4, height-2, m.portBrowserFocus == 1 && !m.reconMenuFocus)
	}
	if split {
		return lipgloss.JoinHorizontal(lipgloss.Top, portPane(listWidth), hostPane(width-listWidth))
	}
	if m.portBrowserFocus == 1 {
		return hostPane(width)
	}
	return portPane(width)
}
