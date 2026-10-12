package tui

import (
	"fmt"
	"strings"
	"time"
	"wscan/internal/discovery"
	"wscan/internal/domain"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func (m model) jobLogRows() int {
	headerRows := 10
	if m.bodyHeight() < 15 {
		headerRows = 5
	}
	return max(1, m.bodyHeight()-2-headerRows)
}

func (m model) updateJobDetails(key string) (tea.Model, tea.Cmd) {
	if m.jobIndex < 0 || m.jobIndex >= len(m.jobs) {
		m.screen = "jobs"
		return m, nil
	}
	j := m.jobs[m.jobIndex]
	visible := m.jobLogRows()
	last := max(0, len(j.journal)-visible)
	switch key {
	case "r":
		m.jobDetailRaw = !m.jobDetailRaw
		m.logOffset = -1
	case "esc", "q":
		m.screen = "jobs"
	case "up", "k":
		if m.logOffset < 0 {
			m.logOffset = last
		}
		m.logOffset = max(0, m.logOffset-1)
	case "down", "j":
		if m.logOffset >= 0 {
			m.logOffset++
			if m.logOffset >= last {
				m.logOffset = -1
			}
		}
	case "end":
		m.logOffset = -1
	case "home":
		m.logOffset = 0
	case "x":
		if j.active() && j.cancel != nil {
			j.cancel()
		}
	case "e":
		return m.updateJobs("e")
	case "enter":
		j.seen = true
		if j.projectID != m.current.ID {
			m.openProject(m.findProject(j.projectID))
		}
		if len(j.targets) == 1 && discovery.IsNetworkTarget(j.targets[0]) {
			m.openHostScope(j.targets[0])
		} else if len(j.targets) == 1 {
			m.openHostScope("")
			m.selectHost(j.targets[0])
		} else if len(j.targets) > 0 {
			m.openHostScope("")
			m.hostIndex = -1
		}
		m.focusCol = 0
		if j.service != nil {
			for i, service := range m.servicesFor(m.currentHost()) {
				if serviceKey(service) == serviceKey(*j.service) {
					m.serviceIndex = i
					m.focusCol = 1
					break
				}
			}
		}
		if j.runID != 0 && !j.opensHostResults() {
			m.openRunResults(j.runID)
			m.projectResultsReturn = "job-details"
		} else {
			m.screen = "desk"
		}
	}
	return m, nil
}

func (m model) viewJobDetails(w int) string {
	if m.jobIndex < 0 || m.jobIndex >= len(m.jobs) {
		return m.renderPanel(w, "Задача недоступна")
	}
	j := m.jobs[m.jobIndex]
	if !m.jobDetailRaw {
		return m.viewJobSummary(w, j)
	}
	lines := []string{
		fmt.Sprintf("Задача #%d · %s", j.id, m.findProject(j.projectID).Name),
		j.label,
		"Область: " + j.scope,
		fmt.Sprintf("Проверок выбрано: %d · запуск в базе: #%d", len(j.checks), j.runID),
		fmt.Sprintf("Начало: %s · %s · %s", j.started.Format("15:04:05"), j.statusLabel(), j.duration().Round(time.Second)),
		j.progressText(min(20, max(3, w/6))) + " " + j.stage,
	}
	if j.service != nil {
		lines = append(lines, "Проверки ограничены выбранным портом; discovery отключён.")
	} else {
		lines = append(lines, strings.Join(j.options, " · "))
	}
	lines = append(lines, "Лог: "+j.logPath)
	if j.logError != "" {
		lines[len(lines)-1] = "Ошибка записи лога: " + j.logError
	}
	lines = append(lines, "", "Журнал · ↑/↓ прокрутка · End последние события")
	if m.bodyHeight() < 15 {
		lines = []string{lines[0], lines[2], lines[5], lines[7], lines[9]}
	}
	visible := m.jobLogRows()
	lo := m.logOffset
	if lo < 0 {
		lo = max(0, len(j.journal)-visible)
	}
	lo = min(max(0, lo), max(0, len(j.journal)-visible))
	lines = append(lines, j.journal[lo:min(len(j.journal), lo+visible)]...)
	for i, line := range lines {
		lines[i] = ansi.Truncate(line, max(1, w-6), "…")
	}
	return m.renderPanel(w, strings.Join(lines, "\n"))
}

func (m model) viewJobSummary(w int, j *job) string {
	project := m.findProject(j.projectID).Name
	if project == "" {
		project = fmt.Sprintf("#%d", j.projectID)
	}
	lines := []string{fmt.Sprintf("Задача #%d · %s", j.id, j.label), "Проект: " + project, "Область: " + j.scope, fmt.Sprintf("Состояние: %s · %s", j.statusLabel(), j.duration().Round(time.Second)), j.progressText(min(20, max(3, w/6))) + " " + j.stage, ""}
	if j.result != nil {
		findings := groupedProjectResults(orderedResults(j.result.Findings))
		lines = append(lines, "РЕЗУЛЬТАТ")
		if summary := j.discoverySummary(); summary != "" {
			lines = append(lines, summary)
		}
		if !j.opensHostResults() || len(findings) > 0 || len(j.result.Errors) > 0 {
			lines = append(lines, resultCounts(findings, len(j.result.Errors)))
		}
		limit := max(1, m.bodyHeight()-len(lines)-5)
		for i, f := range findings {
			if i >= limit {
				lines = append(lines, fmt.Sprintf("Ещё результатов: %d · Enter открыть", len(findings)-i))
				break
			}
			lines = append(lines, projectResultLabel(f))
		}
		if len(findings) == 0 {
			remaining := max(1, m.bodyHeight()-len(lines)-5)
			if services := j.discoveredServices(); len(services) > 0 {
				for i, service := range services {
					if i >= remaining {
						lines = append(lines, fmt.Sprintf("Ещё портов: %d · Enter открыть", len(services)-i))
						break
					}
					lines = append(lines, fmt.Sprintf("%s · %d/%s · %s", service.Host, service.Port, service.Protocol, serviceLabel(service)))
				}
			} else if len(j.result.LiveHosts) > 0 {
				for i, host := range uniqueStrings(j.result.LiveHosts) {
					if i >= remaining {
						lines = append(lines, "Enter — все найденные хосты")
						break
					}
					lines = append(lines, host)
				}
			} else {
				lines = append(lines, "Детектов не сохранено.")
			}
		}
		if len(j.result.Errors) > 0 {
			lines = append(lines, "Ошибка: "+j.result.Errors[0])
		}
	} else if j.errText != "" {
		lines = append(lines, "Ошибка: "+j.errText)
	} else {
		lines = append(lines, "Результат ещё не получен.")
	}
	destination := "результаты"
	if j.opensHostResults() {
		destination = "хосты и порты"
	}
	lines = append(lines, "", "Enter — "+destination+" · r — технический журнал · Esc — задачи")
	for i, line := range lines {
		lines[i] = ansi.Truncate(line, max(1, w-6), "…")
	}
	return m.renderPanel(w, strings.Join(lines, "\n"))
}

func (j *job) opensHostResults() bool {
	return j.kind == jobDiscover || j.kind == jobAlive || j.result != nil && len(j.result.Findings) == 0 && (len(j.result.Services) > 0 || len(j.result.LiveHosts) > 0)
}

func (j *job) discoveredServices() []domain.Service {
	if j.result == nil {
		return nil
	}
	seen := map[string]bool{}
	var services []domain.Service
	for _, s := range j.result.Services {
		if s.Port <= 0 || s.State != "" && !strings.EqualFold(s.State, "open") {
			continue
		}
		if s.Protocol == "" {
			s.Protocol = "tcp"
		}
		s.Protocol = strings.ToLower(s.Protocol)
		key := s.Host + "/" + serviceKey(s)
		if !seen[key] {
			seen[key] = true
			services = append(services, s)
		}
	}
	return services
}

func (j *job) discoverySummary() string {
	if j.result == nil {
		return ""
	}
	hosts := map[string]bool{}
	for _, host := range j.result.LiveHosts {
		if host != "" {
			hosts[host] = true
		}
	}
	services := j.discoveredServices()
	for _, s := range services {
		if s.Host != "" {
			hosts[s.Host] = true
		}
	}
	if len(hosts) == 0 && len(services) == 0 && !j.opensHostResults() {
		return ""
	}
	return fmt.Sprintf("Хосты: %d · Открытые порты: %d", len(hosts), len(services))
}
