package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/catalog"
	"wscan/internal/domain"
)

func (m model) selectionScope() string {
	if m.bulkPort > 0 {
		services, hosts := m.bulkPortServices()
		return fmt.Sprintf("Только %d/%s · %d хостов / %d сервисов · пропущено %d хостов", m.bulkPort, m.bulkProtocol, len(hosts), len(services), len(m.actionHosts)-len(hosts))
	}
	if s := m.actionService; s != nil {
		return fmt.Sprintf("Только %s:%d/%s · %s", s.Host, s.Port, s.Protocol, strings.Join(m.actionHosts, ", "))
	}
	ports := 0
	for _, host := range m.actionHosts {
		ports += len(m.servicesFor(host))
	}
	return fmt.Sprintf("%d целей · %d известных портов · %s", len(m.actionHosts), ports, strings.Join(m.actionHosts, ", "))
}

func (m model) selectedDirections() string {
	set := m.selectedSet()
	directions := map[string]bool{}
	for _, entry := range m.entries {
		if set[entry.Path] {
			directions[catalog.Direction(entry)] = true
		}
	}
	var names []string
	for name := range directions {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func (m model) selectedImpactSummary() string {
	set := m.selectedSet()
	counts := map[string]int{}
	for _, e := range m.entries {
		if set[e.Path] {
			if isBruteEntry(e) {
				counts[bruteCategoryLabel]++
			} else {
				counts[catalog.Impact(e)]++
			}
		}
	}
	var parts []string
	for _, name := range []string{catalog.ImpactDiscovery, catalog.ImpactActive, catalog.ImpactStrong, bruteCategoryLabel} {
		if counts[name] > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", name, counts[name]))
		}
	}
	return strings.Join(parts, " · ")
}

func (m model) openScanReview() (tea.Model, tea.Cmd) {
	if m.actionService == nil && len(m.knownServices(m.actionHosts)) == 0 {
		m.message = "Нет найденных портов. Вернись назад и выбери поиск портов."
		return m, nil
	}
	if len(m.pendingTemplateIDs) == 0 {
		m.message = "Отметь категории или отдельные проверки клавишей Space"
		return m, nil
	}
	m.scanReviewReturn = m.screen
	if !m.scanReviewReady {
		m.scanReviewProject = m.current
		m.scanReviewReady = true
	}
	m.scanReviewIndex = 0
	m.screen = "scan-review"
	m.message = ""
	return m, nil
}

func (m model) updateScanReview(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "left", "right":
		if m.scanReviewIndex == 5 {
			m.scanReviewProject = cycleSpeed(m.scanReviewProject, false, key)
		}
	case "esc":
		m.screen = m.scanReviewReturn
	case "up", "k":
		m.scanReviewIndex = max(0, m.scanReviewIndex-1)
	case "down", "j":
		m.scanReviewIndex = min(5, m.scanReviewIndex+1)
	case "home":
		m.scanReviewIndex = 0
	case "end":
		m.scanReviewIndex = 4
	case "enter":
		if m.scanReviewIndex == 5 {
			m.openSpeedPresets()
			return m, nil
		}
		if m.scanReviewIndex > 0 {
			m.startInput("scan-setting-value")
			m.input = strconv.Itoa(m.scanParameterValues()[m.scanReviewIndex-1])
			return m, nil
		}
		kind := jobChecks
		if m.actionService != nil {
			kind = jobPort
		}
		if m.bulkPort > 0 {
			kind = jobBulkPort
		}
		spec, err := m.buildSpec(actionRow{kind: kind})
		if err != "" {
			m.message = err
			return m, nil
		}
		parameters := m.scanReviewProject
		spec.parameters = &parameters
		m.startLaunch(spec)
		m.scanReviewReady = false
		m.pendingTemplateIDs = nil
		m.screen = "desk"
		m.message = "Запущено: " + spec.label
	}
	return m, nil
}

func (m model) viewScanReview(w int) string {
	body := headingStyle.Render("Запуск проверок") + "\n\n" + m.selectionScope() + "\n\n" +
		"Категории: " + m.selectedDirections() + fmt.Sprintf("\nПроверок: %d\n", len(m.pendingTemplateIDs)) +
		"Воздействие: " + m.selectedImpactSummary() + "\n" +
		"\nИспользуются найденные порты.\nПараметры только этого запуска — ↑/↓, Enter изменить.\n\n" + renderListRow("Запустить — Enter", m.scanReviewIndex == 0, w-4)
	for i, value := range m.scanParameterValues() {
		body += renderListRow(fmt.Sprintf("%s: %d", settingLabels[i], value), m.scanReviewIndex == i+1, w-4)
	}
	body += renderListRow("Пресет скорости: "+speedName(m.scanReviewProject), m.scanReviewIndex == 5, w-4)
	if m.scanReviewProject.RPS == 0 {
		body += "\nRPS 0 — без ограничения скорости запросов.\n"
	}
	body += "\nRPS у Nmap ограничивает портовые пробы, не весь трафик NSE."
	return m.renderPanel(w, body)
}

func (m model) scanParameterValues() []int {
	p := m.scanReviewProject
	return []int{p.RPS, p.Concurrency, p.TimeoutSeconds, p.Retries}
}

func (m model) saveScanSettingValue(value string) (tea.Model, tea.Cmd) {
	m.screen = "scan-review"
	n, err := strconv.Atoi(value)
	minimum := 1
	if m.scanReviewIndex == 4 || m.scanReviewIndex == 1 {
		minimum = 0
	}
	if err != nil || n < minimum {
		m.message = fmt.Sprintf("Введи целое число от %d.", minimum)
		return m, nil
	}
	switch m.scanReviewIndex {
	case 1:
		m.scanReviewProject.RPS = n
	case 2:
		m.scanReviewProject.Concurrency = n
	case 3:
		m.scanReviewProject.TimeoutSeconds = n
	case 4:
		m.scanReviewProject.Retries = n
	}
	m.message = "Параметр изменён только для этого запуска."
	return m, nil
}

// serviceCheckStatus describes the latest matching job without conflating an
// unscanned service with a completed scan that found nothing.
func (m model) serviceCheckStatus(host string, s domain.Service) string {
	for i := len(m.jobs) - 1; i >= 0; i-- {
		j := m.jobs[i]
		if j.projectID != m.current.ID || j.kind == jobDiscover {
			continue
		}
		matches := false
		for _, target := range j.targets {
			if target == host {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		if j.service != nil && (j.service.Host != s.Host || j.service.Port != s.Port || j.service.Protocol != s.Protocol) {
			continue
		}
		switch j.status {
		case statusRunning:
			return "Выполняются · g задачи"
		case statusFailed:
			return "Ошибка · g журнал"
		case statusCancelled:
			return "Остановлены · g журнал"
		case statusDone:
			if j.result != nil && len(j.result.Errors) > 0 {
				return "Завершены с ошибками · g журнал"
			}
			return "Завершены · g журнал"
		}
	}
	if len(m.findingsForService(host, s)) > 0 {
		return "Есть сохранённые результаты"
	}
	return "Нет данных о выполненных проверках"
}
