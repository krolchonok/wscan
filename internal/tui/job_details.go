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
	if m.jobDetailErrors {
		width := max(40, m.width)
		if m.hasSidebar() {
			width -= sidebarWidth(width)
		}
		visible = m.jobErrorRows()
		last = max(0, len(jobErrorLines(j, max(1, width-6)))-visible)
	}
	switch key {
	case "left", "right", "tab", "shift+tab":
		tab := 0
		if m.jobDetailErrors {
			tab = 1
		}
		if m.jobDetailRaw {
			tab = 2
		}
		step := 1
		if key == "left" || key == "shift+tab" {
			step = 2
		}
		tab = (tab + step) % 3
		m.jobDetailErrors, m.jobDetailRaw = tab == 1, tab == 2
		m.logOffset = 0
	case "r":
		m.jobDetailRaw = !m.jobDetailRaw
		m.jobDetailErrors = false
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
	case "pgup":
		if m.logOffset < 0 {
			m.logOffset = last
		}
		m.logOffset = max(0, m.logOffset-visible)
	case "pgdown":
		if m.logOffset >= 0 {
			m.logOffset += visible
			if m.logOffset >= last {
				m.logOffset = -1
			}
		}
	case "x":
		if j.active() && j.cancel != nil {
			j.cancel()
		}
	case "e", "d":
		return m.updateJobs(key)
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
		m.reconMenuFocus = false
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
	if m.jobDetailErrors {
		return m.viewJobErrors(w, j)
	}
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
	lines[1] = m.jobDetailTabs(j)
	if j.service != nil {
		lines = append(lines, "Проверки ограничены выбранным портом; discovery отключён.")
	} else {
		lines = append(lines, strings.Join(j.options, " · "))
	}
	logLabel := j.logPath
	if logLabel == "" {
		logLabel = "сохранён в истории задачи"
	}
	lines = append(lines, "Лог: "+logLabel)
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
	lines := []string{fmt.Sprintf("Задача #%d · %s", j.id, j.label), "Проект: " + project, "Область: " + j.scope, fmt.Sprintf("Состояние: %s · %s", j.statusLabel(), j.duration().Round(time.Second)), j.progressText(min(20, max(3, w/6))) + " " + j.stage, m.jobDetailTabs(j)}
	if j.errText != "" {
		lines = append(lines, strings.Split(ansi.Wrap("Причина: "+ansi.Strip(j.errText), max(1, w-6), ""), "\n")...)
	}
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
		if len(j.taskErrors()) > 0 {
			lines = append(lines, fmt.Sprintf("Все ошибки (%d) — вкладка «Ошибки», →", len(j.taskErrors())))
		}
	} else if j.runID != 0 && !j.active() {
		lines = append(lines, fmt.Sprintf("Сохранено результатов: %d · запуск #%d", j.findings, j.runID))
		if len(j.taskErrors()) > 0 {
			lines = append(lines, fmt.Sprintf("Все ошибки (%d) — вкладка «Ошибки», →", len(j.taskErrors())))
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
	lines = append(lines, "", "Enter — "+destination+" · ←/→ вкладки · r журнал · Esc задачи")
	for i, line := range lines {
		lines[i] = ansi.Truncate(line, max(1, w-6), "…")
	}
	return m.renderPanel(w, strings.Join(lines, "\n"))
}

func (j *job) taskErrors() []string {
	var errs []string
	if j.result != nil {
		errs = append(errs, j.result.Errors...)
	} else {
		errs = append(errs, j.checkErrors...)
	}
	if len(errs) == 0 && j.result != nil {
		for _, f := range j.result.Findings {
			if resultClass(f) == "Ошибка" {
				errs = append(errs, resultTitle(f)+": "+f.Evidence)
			}
		}
	}
	// Legacy snapshots kept only a journal. Recover explicitly reported AD
	// diagnostics so their error list is available after restarting too.
	if j.result == nil && j.checkErrors == nil && len(errs) == 0 {
		for _, line := range j.journal {
			for _, prefix := range []string{"Некоторые SMB/RDP-проверки завершились с ошибкой: ", "Ошибка проверки: ", "DNS SRV пропущен:"} {
				if i := strings.Index(line, prefix); i >= 0 {
					message := line[i:]
					if strings.HasSuffix(prefix, ": ") {
						message = strings.TrimPrefix(message, prefix)
					}
					errs = append(errs, message)
					break
				}
			}
		}
	}
	if j.errText != "" {
		found := false
		for _, e := range errs {
			if e == j.errText {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, j.errText)
		}
	}
	return errs
}

func (m model) jobDetailTabs(j *job) string {
	labels := []string{"Итог", fmt.Sprintf("Ошибки (%d)", len(j.taskErrors())), "Журнал"}
	selected := 0
	if m.jobDetailErrors {
		selected = 1
	}
	if m.jobDetailRaw {
		selected = 2
	}
	labels[selected] = "[" + labels[selected] + "]"
	return strings.Join(labels, " · ") + " · ←/→"
}

func (m model) jobErrorRows() int { return max(1, m.bodyHeight()-7) }

func jobErrorLines(j *job, w int) []string {
	var lines []string
	for i, message := range j.taskErrors() {
		text := fmt.Sprintf("%d. %s", i+1, strings.ReplaceAll(ansi.Strip(message), "\t", "  "))
		lines = append(lines, strings.Split(ansi.Wrap(text, w, ""), "\n")...)
		lines = append(lines, "")
	}
	return lines
}

func (m model) viewJobErrors(w int, j *job) string {
	lines := jobErrorLines(j, max(1, w-6))
	if len(lines) == 0 {
		lines = []string{"Ошибок нет."}
	}
	rows := m.jobErrorRows()
	offset := min(max(0, m.logOffset), max(0, len(lines)-rows))
	if m.logOffset < 0 {
		offset = max(0, len(lines)-rows)
	}
	body := ansi.Truncate(fmt.Sprintf("Задача #%d · %s", j.id, j.label), max(1, w-6), "…") + "\n" + ansi.Truncate(m.jobDetailTabs(j), max(1, w-6), "…") + "\n\n"
	body += strings.Join(lines[offset:min(len(lines), offset+rows)], "\n")
	body += fmt.Sprintf("\nСтроки %d–%d из %d · ↑/↓ прокрутка", offset+1, min(len(lines), offset+rows), len(lines))
	return m.renderPanel(w, body)
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
