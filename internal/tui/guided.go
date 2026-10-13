package tui

import (
	"fmt"
	"net"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/adscan"
	"wscan/internal/app"
)

// Compatibility routes share the current workspace instead of a second menu.
func (m model) viewOverview(w int) string { return m.viewRecon(w) }
func (m model) updateOverview(key string) (tea.Model, tea.Cmd) {
	m.screen = "recon"
	return m.updateRecon(key)
}

func (m *model) openGuidedScan() {
	m.wizardStep = 0
	m.wizardIndex = 0
	m.wizardProfile = 0
	m.wizardScope = strings.Join(m.current.Targets, "\n")
	if len(m.current.Targets) > 0 {
		m.wizardStep = 1
	}
	m.message = ""
	m.screen = "guided-scan"
}

var scanProfileChoices = []int{0, 2, 3}

var guidedProfiles = []string{"Поиск портов и сервисов", "Аудит AD без учётки", "Обнаружение и проверки проекта", "Проверки известных сервисов"}

func (m model) viewGuidedScan(w int) string {
	var b strings.Builder
	title := "Сканирование"
	if m.wizardProfile == 1 {
		title = "Разведка AD"
	}
	b.WriteString(headingStyle.Render(title) + "\n")

	switch m.wizardStep {
	case 0:
		b.WriteString(renderListRow("Цели: "+scanScopeLabel(m.wizardScope)+" · изменить", m.wizardIndex == 0, w))
		b.WriteString(renderListRow("Продолжить →", m.wizardIndex == 1, w))
	case 1:
		b.WriteString(ansi.Truncate("Цели: "+scanScopeLabel(m.wizardScope), max(1, w-4), "…") + "\n\n")
		for i, profile := range scanProfileChoices {
			b.WriteString(renderListRow(guidedProfiles[profile], m.wizardIndex == i, w))
		}
		b.WriteString(renderListRow("Изменить цели", m.wizardIndex == len(scanProfileChoices), w))
	case 2:
		b.WriteString(ansi.Truncate("Цели: "+scanScopeLabel(m.wizardScope), max(1, w-4), "…") + "\n")
		b.WriteString(ansi.Truncate(guidedProfiles[m.wizardProfile], max(1, w-4), "…") + "\n")
		if m.wizardProfile >= 2 {
			b.WriteString(fmt.Sprintf("Выбрано проверок: %d\n", len(m.current.TemplateIDs)))
			if len(m.current.TemplateIDs) == 0 {
				b.WriteString("Нет проверок: выберите их в обзоре.\n")
			}
		}
		label := "Запустить проверку"
		if m.wizardProfile == 0 {
			label = "Настроить порты →"
		}
		b.WriteString(renderListRow(label, true, w-4))

	}
	b.WriteString("\nEnter — действие · Esc — предыдущий шаг")
	body := b.String()
	if m.hasSidebar() {
		var lines []string
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "Enter — действие") {
				lines = append(lines, ansi.Truncate(line, max(1, w-4), "…"))
			}
		}
		body = strings.Join(lines, "\n")
	}
	return m.renderPanel(w, body)
}
func (m model) updateGuidedScan(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		if m.wizardStep > 0 {
			if m.wizardProfile == 1 {
				m.wizardStep = 0
			} else {
				m.wizardStep--
			}
			m.wizardIndex = 0
		} else {
			if m.wizardProfile == 1 {
				m.screen = "ad-menu"
			} else {
				m.screen = "desk"
			}
		}
	case "up", "k":
		m.wizardIndex = max(0, m.wizardIndex-1)
	case "down", "j":
		limit := 1
		if m.wizardStep == 1 {
			limit = len(scanProfileChoices)
		}
		m.wizardIndex = min(limit, m.wizardIndex+1)
	case "enter":
		switch m.wizardStep {
		case 0:
			if m.wizardIndex == 0 {
				m.startInput("guided-scope")
				m.input = m.wizardScope
				return m, nil
			}
			if strings.TrimSpace(m.wizardScope) == "" {
				m.message = "Добавьте область проверки"
				return m, nil
			}
			if m.wizardProfile == 1 {
				m.wizardStep = 2
			} else {
				m.wizardStep = 1
				m.wizardIndex = 0
			}
		case 1:
			if m.wizardIndex == len(scanProfileChoices) {
				m.startInput("guided-scope")
				m.input = m.wizardScope
				return m, nil
			}
			m.wizardProfile = scanProfileChoices[min(max(0, m.wizardIndex), len(scanProfileChoices)-1)]
			m.wizardStep = 2
			m.wizardIndex = 0
			if m.wizardProfile == 0 {
				m.actionHosts = strings.Fields(m.wizardScope)
				m.actionService = nil
				m.openDiscOptions()
				m.wizardStep = 1
				return m, nil
			}
		case 2:
			hosts := strings.Fields(m.wizardScope)
			kind := []string{jobDiscover, jobAD, jobFull, jobChecks}[m.wizardProfile]
			if kind == jobDiscover {
				m.actionHosts = append([]string(nil), hosts...)
				m.actionService = nil
				m.openDiscOptions()
				return m, nil
			}
			if kind == jobAD {
				if err := adscan.ValidateTargets(hosts); err != nil {
					m.message = err.Error()
					return m, nil
				}
			}
			if m.shared != nil {
				r := app.ScanRequest{ProjectID: m.current.ID, Spec: app.Spec{Kind: kind, Hosts: hosts, TemplateIDs: m.current.TemplateIDs, DiscNoPing: true}, DNS: m.adScanDNS}
				if kind == jobAD {
					r.CIDR = strings.Join(hosts, " ")
				}
				snapshot, err := m.shared.StartScan(m.ctx, r, m.jobSource(), "")
				if err != nil {
					m.message = err.Error()
					return m, nil
				}
				m.addSharedJob(snapshot)
			} else if kind == jobAD {
				m.launchADScan(strings.Join(hosts, " "))
			} else {
				m.startLaunch(launchSpec{kind: kind, label: guidedProfiles[m.wizardProfile], hosts: hosts, templateIDs: m.current.TemplateIDs, discNoPing: true})
			}
			m.jobsReturn = "desk"
			m.screen = "jobs"
			m.message = "Задача запущена. Enter — подробности, x — остановить."
		}
	}
	return m, nil
}

// Summarize the scope for display without changing the requested targets.
func scanScopeLabel(scope string) string {
	targets := uniqueStrings(strings.Fields(scope))
	if len(targets) == 0 {
		return "не заданы"
	}
	var ranges []string
	var networks []*net.IPNet
	for _, target := range targets {
		if _, network, err := net.ParseCIDR(target); err == nil {
			ranges = append(ranges, target)
			networks = append(networks, network)
		}
	}
	if len(ranges) == 0 {
		if len(targets) <= 3 {
			return strings.Join(targets, ", ")
		}
		return fmt.Sprintf("%d целей · %s, %s…", len(targets), targets[0], targets[1])
	}
	extra := 0
	for _, target := range targets {
		if _, _, err := net.ParseCIDR(target); err == nil {
			continue
		}
		covered := false
		if ip := net.ParseIP(target); ip != nil {
			for _, network := range networks {
				if network.Contains(ip) {
					covered = true
					break
				}
			}
		}
		if !covered {
			extra++
		}
	}
	label := strings.Join(ranges, ", ")
	if extra > 0 {
		label += fmt.Sprintf(" · ещё %d целей", extra)
	}
	return label
}
