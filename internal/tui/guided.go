package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/adscan"
	"wscan/internal/app"
)

func (m model) viewOverview(w int) string {
	var b strings.Builder
	b.WriteString(headingStyle.Render("Обзор проекта") + "\n\n")
	b.WriteString("Область: " + strings.Join(m.current.Targets, ", ") + "\n")
	b.WriteString(fmt.Sprintf("Хостов: %d · запусков: %d\n\n", len(m.hostOrder), len(m.history)))
	for i, title := range []string{"Начать проверку…", "Открыть хосты", "Открыть результаты", "Открыть задачи", "Учётные записи", "Настройки проекта"} {
		b.WriteString(renderListRow(title, m.overviewIndex == i, w))
	}
	if m.webURL != "" {
		b.WriteString("\nWeb: " + m.webURL + "\n")
	}
	b.WriteString("\nВыберите действие стрелками и нажмите Enter.\nМастер: область → профиль → перед запуском.\nСтарые клавиши 1–5 сохранены; 0 — этот обзор.")
	return m.renderPanel(w, b.String())
}
func (m model) updateOverview(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.overviewIndex = max(0, m.overviewIndex-1)
	case "down", "j":
		m.overviewIndex = min(5, m.overviewIndex+1)
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
		}
	}
	return m, nil
}
func (m *model) openGuidedScan() {
	m.wizardStep = 0
	m.wizardIndex = 0
	m.wizardProfile = 0
	m.wizardScope = strings.Join(m.current.Targets, "\n")
	m.message = ""
	m.screen = "guided-scan"
}

var guidedProfiles = []string{"Поиск портов и сервисов", "Аудит AD без учётки", "Обнаружение и проверки проекта", "Проверки известных сервисов"}

func (m model) viewGuidedScan(w int) string {
	var b strings.Builder
	b.WriteString(headingStyle.Render("Начать проверку") + "\n")
	b.WriteString(fmt.Sprintf("Шаг %d / 3 · Область → Профиль → Перед запуском\n\n", m.wizardStep+1))
	switch m.wizardStep {
	case 0:
		b.WriteString(renderListRow("Область: "+strings.ReplaceAll(m.wizardScope, "\n", ", ")+" · Enter изменить", m.wizardIndex == 0, w))
		b.WriteString(renderListRow("Продолжить →", m.wizardIndex == 1, w))
		b.WriteString("\nУкажите CIDR, IP или URL. Только эти цели попадут в запуск.")
	case 1:
		for i, p := range guidedProfiles {
			b.WriteString(renderListRow(p, m.wizardIndex == i, w))
		}
		b.WriteString("\nEnter выбирает профиль и открывает сводку.\nAD: один частный IPv4 CIDR; DNS/домены настраиваются\nчерез прежний AD-экран в разделе «Взаимодействие».")
	case 2:
		b.WriteString("Проект: " + m.current.Name + "\nОбласть: " + strings.ReplaceAll(m.wizardScope, "\n", ", ") + "\nПрофиль: " + guidedProfiles[m.wizardProfile] + "\n")
		b.WriteString(fmt.Sprintf("HTTP: %d RPS · %d параллельно\nDiscovery: %d RPS · %d параллельно\n", m.current.RPS, m.current.Concurrency, m.current.DiscoveryRPS, m.current.DiscoveryConcurrency))
		if m.wizardProfile == 0 {
			b.WriteString("Типовые TCP-порты; определение сервисов. ICMP не требуется.\n")
		}
		if m.wizardProfile == 1 {
			b.WriteString("AD-порты → LDAP → DNS-топология → SMB/RDP → сводка.\nДо 250 TCP-проб/с; без учётки и изменений на узлах.\n")
		}
		if m.wizardProfile >= 2 {
			b.WriteString(fmt.Sprintf("Проверок проекта: %d; существующие разрешения сохраняются.\n", len(m.current.TemplateIDs)))
		}
		b.WriteString("\n" + renderListRow("Запустить проверку", true, w))
	}
	b.WriteString("\n\nEnter — выбранное действие · Esc — предыдущий шаг")
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
				if len(hosts) != 1 {
					m.message = "AD-профиль принимает один CIDR"
					return m, nil
				}
				if _, err := adscan.ValidatePrivateSubnet(hosts[0]); err != nil {
					m.message = err.Error()
					return m, nil
				}
			}
			if m.shared != nil {
				r := app.ScanRequest{ProjectID: m.current.ID, Spec: app.Spec{Kind: kind, Hosts: hosts, TemplateIDs: m.current.TemplateIDs, DiscNoPing: true}, DNS: m.adScanDNS}
				if kind == jobAD {
					r.CIDR = hosts[0]
				}
				snapshot, err := m.shared.StartScan(m.ctx, r, m.jobSource(), "")
				if err != nil {
					m.message = err.Error()
					return m, nil
				}
				m.addSharedJob(snapshot)
			} else if kind == jobAD {
				m.launchADScan(hosts[0])
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
