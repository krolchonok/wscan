package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/adscan"
	"wscan/internal/app"
)

var overviewActions = []string{"Начать проверку…", "Открыть хосты", "Открыть результаты", "Открыть задачи", "Учётные записи", "Настройки проекта", "Выбрать проверки проекта"}

func (m model) viewOverview(w int) string {
	var b strings.Builder
	b.WriteString(headingStyle.Render("Обзор проекта") + "\n")
	b.WriteString(ansi.Truncate("Область: "+strings.Join(m.current.Targets, ", "), max(1, w-4), "…") + "\n")
	b.WriteString(fmt.Sprintf("Хостов: %d · запусков: %d · проверок: %d\n", len(m.hostOrder), len(m.history), len(m.current.TemplateIDs)))
	lo, hi := windowRange(m.overviewIndex, len(overviewActions), max(1, m.bodyHeight()-7))
	for i := lo; i < hi; i++ {
		b.WriteString(renderListRow(overviewActions[i], m.overviewIndex == i, w-4))
	}
	if hi < len(overviewActions) {
		b.WriteString("↓ Ещё действия\n")
	}
	return m.renderPanel(w, b.String())
}
func (m model) updateOverview(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.overviewIndex = max(0, m.overviewIndex-1)
	case "down", "j":
		m.overviewIndex = min(len(overviewActions)-1, m.overviewIndex+1)
	case "s":
		m.openGuidedScan()
	case "esc":
		m.screen = "projects"
	case "enter":
		switch m.overviewIndex {
		case 0:
			m.openGuidedScan()
		case 1:
			m.openHostScope("")
		case 2:
			m.openProjectResults()
		case 3:
			m.jobsReturn = m.screen
			m.screen = "jobs"
		case 4:
			m.openCredentials()
		case 5:
			m.screen = "settings"
		case 6:
			m.pendingTemplateIDs = nil
			m.openCatalog(false, "overview")
		}
	}
	return m, nil
}
func (m *model) openGuidedScan() {
	m.wizardStep = 0
	m.wizardIndex = 0
	m.wizardProfile = 0
	m.wizardScope = strings.Join(m.current.Targets, "\n")
	if len(m.current.Targets) > 0 {
		m.wizardIndex = 1
	}
	m.message = ""
	m.screen = "guided-scan"
}

var guidedProfiles = []string{"Поиск портов и сервисов", "Аудит AD без учётки", "Обнаружение и проверки проекта", "Проверки известных сервисов"}

func (m model) viewGuidedScan(w int) string {
	var b strings.Builder
	b.WriteString(headingStyle.Render("Начать проверку") + "\n")
	b.WriteString(fmt.Sprintf("Шаг %d / 3 · Область → Профиль → Перед запуском\n", m.wizardStep+1))
	switch m.wizardStep {
	case 0:
		b.WriteString(renderListRow("Область: "+strings.ReplaceAll(m.wizardScope, "\n", ", ")+" · Enter изменить", m.wizardIndex == 0, w))
		b.WriteString(renderListRow("Продолжить →", m.wizardIndex == 1, w))
		b.WriteString("\nУкажите CIDR, IP или URL. Только эти цели попадут в запуск.")
	case 1:
		for i, p := range guidedProfiles {
			b.WriteString(renderListRow(p, m.wizardIndex == i, w))
		}
		b.WriteString("\nEnter выбирает профиль и открывает сводку.\nAD: IP, имена хостов и частные IPv4 CIDR; DNS/домены\nчерез прежний AD-экран в разделе «Взаимодействие».")
	case 2:
		b.WriteString(ansi.Truncate("Проект: "+m.current.Name, max(1, w-4), "…") + "\n")
		b.WriteString(ansi.Truncate("Область: "+strings.ReplaceAll(m.wizardScope, "\n", ", "), max(1, w-4), "…") + "\n")
		b.WriteString(ansi.Truncate("Профиль: "+guidedProfiles[m.wizardProfile], max(1, w-4), "…") + "\n")
		if m.wizardProfile == 1 {
			b.WriteString("До 250 TCP-проб/с · AD без учётки\n")
		} else {
			b.WriteString(fmt.Sprintf("Discovery: %d/с · проверки: %d RPS\n", m.current.DiscoveryRPS, m.current.RPS))
		}
		if m.wizardProfile >= 2 {
			b.WriteString(fmt.Sprintf("Выбрано проверок: %d\n", len(m.current.TemplateIDs)))
			if len(m.current.TemplateIDs) == 0 {
				b.WriteString("Нет проверок: выберите их в обзоре.\n")
			}
		}
		b.WriteString(renderListRow("Запустить проверку", true, w-4))

	}
	b.WriteString("\nEnter — действие · Esc — предыдущий шаг")
	return m.renderPanel(w, b.String())
}
func (m model) updateGuidedScan(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		if m.wizardStep > 0 {
			m.wizardStep--
			m.wizardIndex = 0
		} else {
			m.screen = "overview"
		}
	case "up", "k":
		m.wizardIndex = max(0, m.wizardIndex-1)
	case "down", "j":
		limit := 1
		if m.wizardStep == 1 {
			limit = len(guidedProfiles) - 1
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
			m.wizardStep = 1
			m.wizardIndex = m.wizardProfile
		case 1:
			m.wizardProfile = m.wizardIndex
			m.wizardStep = 2
			m.wizardIndex = 0
		case 2:
			hosts := strings.Fields(m.wizardScope)
			kind := []string{jobDiscover, jobAD, jobFull, jobChecks}[m.wizardProfile]
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
			m.jobsReturn = "overview"
			m.screen = "jobs"
			m.message = "Задача запущена. Enter — подробности, x — остановить."
		}
	}
	return m, nil
}
