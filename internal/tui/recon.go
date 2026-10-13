package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var reconActions = []string{"Сканировать", "AD-разведка", "Добавить цель", "Фильтр машин", "Учётки", "Задачи", "Результаты", "Проверки", "Настройки", "Проекты", "Машины", "← Назад"}

var reconFilters = []string{"Все машины", "AD / Windows", "С результатами"}

// Roles are hints from observed services, never claims of confirmed AD roles.
func (m model) reconRole(host string) string {
	windows, web := false, false
	for _, s := range m.servicesFor(host) {
		switch s.Port {
		case 88, 389, 636, 3268, 3269:
			return "AD?"
		case 445, 139, 3389, 5985, 5986:
			windows = true
		}
		name := strings.ToLower(s.Name)
		if strings.Contains(name, "http") {
			web = true
		}
	}
	if windows {
		return "Windows?"
	}
	if web {
		return "Web"
	}
	return "—"
}

func (m model) reconHosts() []string {
	var hosts []string
	for _, host := range m.hostOrder {
		role := m.reconRole(host)
		if m.reconFilter == 1 && role != "AD?" && role != "Windows?" {
			continue
		}
		if m.reconFilter == 2 && len(m.findingsFor(host)) == 0 {
			continue
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func reconCell(s string, width int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
	s = ansi.Truncate(s, max(1, width), "…")
	return s + strings.Repeat(" ", max(0, width-ansi.StringWidth(s)))
}

var reconCardActions = []string{"Сервисы", "Сканировать порты", "Проверить машину", "Подключиться", "Результаты", "← К списку машин"}

func (m model) selectedReconHost() string {
	hosts := m.reconHosts()
	if len(hosts) == 0 {
		return ""
	}
	return hosts[min(max(0, m.reconIndex), len(hosts)-1)]
}

func (m model) viewRecon(w int) string {
	height := m.bodyHeight()
	if w < 64 {
		if m.reconCardFocus {
			return renderColumn(m.reconCard(w-4), w-4, height-2, true)
		}
		return renderColumn(m.reconHostList(w-4), w-4, height-2, !m.reconMenuFocus)
	}
	left := max(28, w*42/100)
	return lipgloss.JoinHorizontal(lipgloss.Top,
		renderColumn(m.reconHostList(left-4), left-4, height-2, !m.reconMenuFocus && !m.reconCardFocus),
		renderColumn(m.reconCard(w-left-4), w-left-4, height-2, !m.reconMenuFocus && m.reconCardFocus))
}

func (m model) reconHostList(width int) string {
	var body strings.Builder
	hosts := m.reconHosts()
	body.WriteString(headingStyle.Render("Разведка сети · Машины") + "\n")
	body.WriteString(ansi.Truncate(reconFilters[m.reconFilter], max(1, width), "…") + "\n")
	if len(hosts) == 0 {
		return body.String() + "\nНет машин.\nВыберите «Добавить цель»\nили «Сканировать» в меню."
	}
	lo, hi := windowRange(m.reconIndex, len(hosts), max(1, m.bodyHeight()-6))
	body.WriteString(fitContent(strings.TrimSuffix(moreLine(lo, true), "\n"), width, 1) + "\n")
	for i := lo; i < hi; i++ {
		selected := i == m.reconIndex && !m.reconMenuFocus && !m.reconCardFocus
		body.WriteString(renderListRow(m.reconHostRow(hosts[i])[0], selected, width+4))
	}
	body.WriteString(fitContent(strings.TrimSuffix(moreLine(len(hosts)-hi, false), "\n"), width, 1) + "\n")
	return body.String()
}

// Each table entry keeps the machine's saved facts beside its address.
func (m model) reconHostRow(host string) []string {
	names := append([]string(nil), m.namesForHost(host)...)
	var operatingSystems, services []string
	for _, svc := range m.servicesFor(host) {
		if svc.DetectedHostname != "" {
			names = append(names, svc.DetectedHostname)
		}
		if svc.OS != "" {
			operatingSystems = append(operatingSystems, svc.OS)
		}
		protocol := svc.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		label := fmt.Sprintf("%d/%s", svc.Port, protocol)
		if svc.Name != "" {
			label += " " + svc.Name
		}
		services = append(services, label)
	}
	findings := m.findingsFor(host)
	for _, line := range smbSummary(findings) {
		if strings.HasPrefix(line, "Машина: ") {
			names = append(names, strings.TrimPrefix(line, "Машина: "))
		}
		if strings.HasPrefix(line, "ОС сообщает: ") {
			operatingSystems = append(operatingSystems, strings.TrimPrefix(line, "ОС сообщает: "))
		}
	}
	title := host
	if len(names) > 0 {
		title += " · " + strings.Join(uniqueStrings(names), ", ")
	}
	os := strings.Join(uniqueStrings(operatingSystems), ", ")
	rows := []string{title}
	if os != "" {
		rows = append(rows, "ОС: "+os)
	}
	if len(services) > 0 {
		rows = append(rows, strings.Join(services, ", "))
	}
	if len(findings) > 0 {
		rows = append(rows, fmt.Sprintf("Рез.: %d", len(findings)))
	}
	return []string{strings.Join(rows, " · ")}
}

func (m model) reconInformation(host string, width int) []string {
	var data []string
	add := func(line string) {
		line = ansi.Strip(line)
		line = strings.Map(func(r rune) rune {
			if r < 32 || r == 127 {
				return ' '
			}
			return r
		}, line)
		data = append(data, strings.Split(ansi.Wrap(line, max(1, width), ""), "\n")...)
	}
	names := strings.Join(m.namesForHost(host), ", ")
	if names == "" {
		names = "не получены"
	}
	add("DNS: " + names)
	add("Роль: " + m.reconRole(host) + " (? — по сервисам)")
	services := m.servicesFor(host)
	findings := m.findingsFor(host)
	add(resultCounts(findings))
	var os, devices []string
	for _, svc := range services {
		if svc.OS != "" {
			os = append(os, svc.OS)
		}
		if svc.DeviceType != "" {
			devices = append(devices, svc.DeviceType)
		}
	}
	if len(os) > 0 {
		add("ОС: " + strings.Join(uniqueStrings(os), ", "))
	} else {
		add("ОС: не определена")
	}
	if len(devices) > 0 {
		add("Устройство: " + strings.Join(uniqueStrings(devices), ", "))
	}
	for _, line := range smbSummary(findings) {
		add(line)
	}
	add(fmt.Sprintf("Сервисы (%d)", len(services)))
	if len(services) == 0 {
		add("Сервисы ещё не обнаружены")
	}
	for _, svc := range services {
		protocol := svc.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		name := svc.Name
		if name == "" {
			name = "не определён"
		}
		line := fmt.Sprintf("%d/%s · %s", svc.Port, protocol, name)
		if svc.Tunnel != "" {
			line += " · " + svc.Tunnel
		}
		if svc.State != "" {
			line += " · " + svc.State
		}
		add(line)
		if product := strings.TrimSpace(svc.Product + " " + svc.Version); product != "" {
			add("  Продукт: " + product)
		}
		if svc.DetectedHostname != "" {
			add("  Имя сервиса: " + svc.DetectedHostname)
		}
		if svc.Info != "" {
			add("  Сведения: " + svc.Info)
		}
		if len(svc.CPE) > 0 {
			add("  CPE: " + strings.Join(svc.CPE, ", "))
		}
	}
	if len(findings) > 0 {
		add("Результаты проверок")
		for _, finding := range findings {
			add(resultLabel(finding))
		}
	}
	return data
}

func (m model) reconInfoRows() int {
	return max(1, m.bodyHeight()-11)
}

func (m model) reconCard(width int) string {
	host := m.selectedReconHost()
	if host == "" {
		return headingStyle.Render("Карточка машины") + "\n\nВыберите машину слева."
	}
	var body strings.Builder
	body.WriteString(headingStyle.Render(ansi.Truncate(host, max(1, width), "…")) + "\n")
	lines := m.reconInformation(host, width)
	rows := m.reconInfoRows()
	offset := min(m.reconInfoOffset, max(0, len(lines)-rows))
	body.WriteString(strings.Join(lines[offset:min(len(lines), offset+rows)], "\n") + "\n")
	if len(lines) > rows {
		body.WriteString(mutedStyle.Render(ansi.Truncate(fmt.Sprintf("%d–%d / %d · PgUp/PgDn сведения", offset+1, min(len(lines), offset+rows), len(lines)), max(1, width), "…")) + "\n")
	}
	body.WriteString(headingStyle.Render("Действия") + "\n")
	lo, hi := windowRange(m.reconHostAction, len(reconCardActions), min(len(reconCardActions), max(1, m.bodyHeight()-5)))
	for i := lo; i < hi; i++ {
		body.WriteString(renderListRow(reconCardActions[i], m.reconCardFocus && !m.reconMenuFocus && i == m.reconHostAction, width+4))
	}
	return body.String()
}

func (m *model) selectReconHost() bool {
	hosts := m.reconHosts()
	if len(hosts) == 0 {
		m.message = "Выберите машину или запустите разведку"
		return false
	}
	m.reconIndex = min(max(0, m.reconIndex), len(hosts)-1)
	for i, host := range m.hostOrder {
		if host == hosts[m.reconIndex] {
			m.hostIndex = i
			m.serviceIndex = 0
			m.focusCol = 0
			return true
		}
	}
	return false
}

func (m model) updateRecon(key string) (tea.Model, tea.Cmd) {
	if next, cmd, ok := m.selectSidebarShortcut(key); ok {
		return next, cmd
	}
	switch key {
	case "left":
		if m.reconCardFocus && !m.reconMenuFocus {
			m.reconCardFocus = false
		} else {
			m.reconMenuFocus = true
		}
		return m, nil
	case "right":
		if m.reconMenuFocus {
			m.reconMenuFocus = false
			m.reconCardFocus = false
		} else if m.selectedReconHost() != "" {
			m.reconCardFocus = true
		}
		return m, nil
	case "tab", "shift+tab":
		if key == "shift+tab" {
			if m.reconMenuFocus {
				m.reconMenuFocus = false
				m.reconCardFocus = true
			} else if m.reconCardFocus {
				m.reconCardFocus = false
			} else {
				m.reconMenuFocus = true
			}
		} else {
			if m.reconMenuFocus {
				m.reconMenuFocus = false
				m.reconCardFocus = false
			} else if !m.reconCardFocus {
				m.reconCardFocus = true
			} else {
				m.reconCardFocus = false
				m.reconMenuFocus = true
			}
		}
		return m, nil
	}
	if m.reconMenuFocus {
		next, cmd, _ := m.updateSidebar(key)
		return next, cmd
	}
	if m.reconCardFocus {
		switch key {
		case "up":
			m.reconHostAction = max(0, m.reconHostAction-1)
		case "down":
			m.reconHostAction = min(len(reconCardActions)-1, m.reconHostAction+1)
		case "pgdown":
			width := m.width
			if width <= 0 {
				width = 100
			}
			if m.hasSidebar() {
				width -= sidebarWidth(width)
			}
			if width >= 64 {
				width -= max(28, width*42/100)
			}
			last := max(0, len(m.reconInformation(m.selectedReconHost(), max(1, width-4)))-m.reconInfoRows())
			m.reconInfoOffset = min(last, m.reconInfoOffset+m.reconInfoRows())
		case "pgup":
			m.reconInfoOffset = max(0, m.reconInfoOffset-m.reconInfoRows())
		case "home":
			m.reconInfoOffset = 0
		case "enter":
			return m.runReconCardAction()
		}
		return m, nil
	}
	switch key {
	case "up":
		m.reconIndex = max(0, m.reconIndex-1)
		m.reconHostAction = 0
		m.reconInfoOffset = 0
	case "down":
		m.reconIndex = min(max(0, len(m.reconHosts())-1), m.reconIndex+1)
		m.reconHostAction = 0
		m.reconInfoOffset = 0
	case "home":
		m.reconIndex = 0
		m.reconInfoOffset = 0
	case "end":
		m.reconIndex = max(0, len(m.reconHosts())-1)
		m.reconInfoOffset = 0
	case "enter":
		if m.selectedReconHost() != "" {
			m.reconCardFocus = true
			m.reconHostAction = 0
		}
	}
	return m, nil
}

func (m model) runReconCardAction() (tea.Model, tea.Cmd) {
	if !m.selectReconHost() {
		return m, nil
	}
	switch m.reconHostAction {
	case 0:
		m.screen = "desk"
		m.focusCol = 1
	case 1, 2:
		action := m.reconHostAction
		m.focusCol = 0
		m.openActionMenu(nil)
		m.actionHosts = []string{m.currentHost()}
		if action == 1 {
			m.actionIndex = 1
		} else {
			m.actionIndex = 0
		}
		return m.updateActionMenu("enter")
	case 3:
		m.openInteractionMenu()
		m.interactionReturn = "recon"
	case 4:
		m.openScopedResults(resultScope{host: m.currentHost()})
	case 5:
		m.reconCardFocus = false
	}
	return m, nil
}

func (m model) runReconAction() (tea.Model, tea.Cmd) {
	switch m.reconMenuIndex {
	case 0:
		m.openGuidedScan()
	case 1:
		m.adMenuIndex = 0
		m.screen = "ad-menu"
	case 2:
		m.startInput("add-target")
	case 3:
		if m.sidebarEnabled {
			m.actionIndex = 0
			m.screen = "host-selection"
			return m, nil
		}
		m.screen = "recon"
		m.reconCardFocus = false
		m.reconInfoOffset = 0
		m.reconFilter = (m.reconFilter + 1) % len(reconFilters)
		m.reconIndex = 0
		m.reconMenuFocus = false
	case 4:
		m.openCredentials()
	case 5:
		m.jobsReturn = "desk"
		m.screen = "jobs"
	case 6:
		m.openProjectResults()
	case 7:
		m.checkMenuIndex = 0
		m.screen = "checks-menu"
	case 8:
		m.screen = "settings"
	case 9:
		m.screen = "projects"
	case 10:
		m.reconCardFocus = false
		m.openHostScope("")
	case 11:
		return m.sidebarBack()
	}
	return m, nil
}

func (m model) viewReconHostMenu(w int) string { m.reconCardFocus = true; return m.viewRecon(w) }
func (m model) updateReconHostMenu(key string) (tea.Model, tea.Cmd) {
	m.screen = "recon"
	m.reconCardFocus = true
	return m.updateRecon(key)
}
