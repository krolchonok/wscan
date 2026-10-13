package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/adscan"
	"wscan/internal/app"
)

func (m *model) openADScan() {
	m.adScanReturn = m.screen
	m.adScanNewProject = m.current.ID == 0
	m.adScanDNS = adscan.DNSOptions{}
	m.adScanAdvanced = false
	var err error
	m.adNetworks, err = adscan.LocalNetworks()
	m.adNetworkIndex = 0
	m.serviceIndex = 0
	m.adScanDone = 0
	m.adScanTotal = 0
	m.adScanResult = nil
	m.adScanError = ""
	if err != nil {
		m.adScanError = err.Error()
	}
	m.message = ""
	m.screen = "ad-scan"
}

func (m model) updateADScan(key string) (tea.Model, tea.Cmd) {
	if m.adScanRunning {
		switch key {
		case "x", "esc", "q":
			if job := m.jobByID(m.adScanJobID); job != nil && job.cancel != nil {
				job.cancel()
			}
			m.message = "Останавливаю сканирование…"
		}
		return m, nil
	}
	if m.adScanResult != nil && m.adScanError == "" {
		switch key {
		case "up", "k":
			if m.serviceIndex > 0 {
				m.serviceIndex--
			}
			return m, nil
		case "down", "j":
			if m.serviceIndex+1 < len(m.adScanResult.Hosts) {
				m.serviceIndex++
			}
			return m, nil
		}
	}
	switch key {
	case "a":
		m.adScanAdvanced = !m.adScanAdvanced
	case "d", "n", "b":
		if m.adScanAdvanced {
			action := map[string]string{"d": "ad-recon-dns", "n": "ad-recon-domains", "b": "ad-recon-budget"}[key]
			m.startInput(action)
			switch key {
			case "d":
				m.input = strings.Join(m.adScanDNS.Servers, ", ")
			case "n":
				m.input = strings.Join(m.adScanDNS.Domains, ", ")
			case "b":
				m.input = fmt.Sprint(m.adScanDNS.MaxQueries)
				if m.adScanDNS.MaxQueries == 0 {
					m.input = "1024"
				}
			}
			return m, nil
		}
	case "p":
		if m.current.ID == 0 {
			m.message = "Текущий проект не открыт; результаты будут сохранены в новый проект"
		} else {
			m.adScanNewProject = !m.adScanNewProject
			m.message = ""
		}
	case "up", "k":
		if m.adNetworkIndex > 0 {
			m.adNetworkIndex--
		}
	case "down", "j":
		if m.adNetworkIndex < len(m.adNetworks) {
			m.adNetworkIndex++
		}
	case "r":
		var err error
		m.adNetworks, err = adscan.LocalNetworks()
		m.adNetworkIndex = 0
		m.adScanResult = nil
		m.serviceIndex = 0
		m.adScanError = ""
		if err != nil {
			m.adScanError = err.Error()
		}
	case "esc", "q":
		m.screen = m.adScanReturn
		m.message = ""
	case "enter":
		if m.adNetworkIndex == len(m.adNetworks) {
			m.startInput("ad-cidr")
			return m, nil
		}
		selected := m.adNetworks[m.adNetworkIndex]
		m.adScanRunning = true
		m.adScanDone = 0
		m.adScanTotal = 0
		m.adScanResult = nil
		m.serviceIndex = 0
		m.adScanError = ""
		m.message = ""
		m.launchADScan(selected.CIDR)
	}
	return m, nil
}

func (m *model) launchADScan(cidr string) {
	if m.shared != nil {
		snapshot, err := m.shared.StartScan(m.ctx, app.ScanRequest{ProjectID: m.current.ID, Spec: app.Spec{Kind: jobAD}, CIDR: cidr, NewProject: m.adScanNewProject, DNS: m.adScanDNS}, m.jobSource(), "")
		if err != nil {
			m.adScanRunning = false
			m.adScanError = err.Error()
			return
		}
		m.addSharedJob(snapshot)
		m.adScanJobID = snapshot.ID
		return
	}

	worker := *m // Capture the destination before the background scan starts.
	m.jobSeq++
	id := m.jobSeq
	ctx, cancel := context.WithCancel(m.ctx)
	j := &job{
		id: id, kind: jobAD,
		label: "AD scan " + cidr, targets: []string{cidr},
		status: statusRunning, stage: "подготовка диапазона…",
		started: time.Now(), cancel: cancel, scope: cidr,
	}
	if !worker.adScanNewProject && worker.current.ID != 0 {
		j.projectID = worker.current.ID
		j.options = []string{"Сохранение: текущий проект " + worker.current.Name}
	} else {
		j.options = []string{"Сохранение: новый проект"}
	}
	j.options = append(j.options, "DNS: найденные серверы + "+strings.Join(worker.adScanDNS.Servers, ", "), "Домены: найденные + "+strings.Join(worker.adScanDNS.Domains, ", "))
	budget := worker.adScanDNS.MaxQueries
	if budget == 0 {
		budget = 1024
	}
	j.options = append(j.options, fmt.Sprintf("DNS SRV: лимит %d запросов", budget))
	m.jobs = append(m.jobs, j)
	m.adScanJobID = id
	m.initJobLog(j)
	ch := m.jobEvents
	go func() {
		result, details, projectID, projectName, err := worker.runADScan(ctx, cidr, func(stage string, counts ...int) {
			ev := jobEvent{id: id, stage: stage, hasProgress: len(counts) == 2}
			if len(counts) == 2 {
				ev.completed, ev.total = counts[0], counts[1]
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
			}
		})
		ch <- jobEvent{id: id, done: true, result: result, adResult: details, projectID: projectID, projectName: projectName, err: err}
	}()
}

// adResultProject adds discovered targets without replacing existing scope or settings.

func (m model) viewADScan(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("AD-аудит сети") + "\n")
	destination := "новый проект"
	if !m.adScanNewProject && m.current.ID != 0 {
		destination = fmt.Sprintf("текущий проект %q (#%d)", m.current.Name, m.current.ID)
	}
	body.WriteString("Сохранение: " + destination + " · p переключить\n")
	body.WriteString("1. Выберите подсеть  →  2. Enter: запустить  →  3. Результаты в проекте\n")
	body.WriteString("AD/Windows-разведка без учётки. a — дополнительные параметры DNS\n\n")
	if m.adScanAdvanced {
		servers, domains := strings.Join(m.adScanDNS.Servers, ", "), strings.Join(m.adScanDNS.Domains, ", ")
		if servers == "" {
			servers = "автоматически"
		}
		if domains == "" {
			domains = "автоматически"
		}
		budget := m.adScanDNS.MaxQueries
		if budget == 0 {
			budget = 1024
		}
		body.WriteString(fmt.Sprintf("d DNS: %s\nn Домены: %s\nb Лимит DNS-запросов: %d\nDNS дополняет найденные данные; адреса SRV не расширяют область.\n\n", servers, domains, budget))
	}
	if len(m.adNetworks) == 0 {
		body.WriteString("Активные частные IPv4-интерфейсы не найдены. Можно указать CIDR вручную.\n")
		body.WriteString(renderListRow("Ввести подсеть вручную…", m.adNetworkIndex == 0 && !m.adScanRunning, w))
	} else {
		body.WriteString("Локальные подсети (сканируется только выбранная):\n")
		for i, network := range m.adNetworks {
			line := fmt.Sprintf("%-14s  %s", network.Interface, network.CIDR)
			if i == m.adNetworkIndex {
				line += "  ·  ~" + adscan.EstimateDuration(network.CIDR).Round(time.Second).String()
			}
			body.WriteString(renderListRow(line, i == m.adNetworkIndex && !m.adScanRunning, w))
		}
		body.WriteString(renderListRow("Ввести подсеть вручную…", m.adNetworkIndex == len(m.adNetworks) && !m.adScanRunning, w))
	}

	if m.adScanRunning {
		body.WriteString("\n" + headingStyle.Render("Сканирование") + "\n")
		if m.adScanTotal > 0 {
			percent := min(int64(100), int64(m.adScanDone)*100/int64(m.adScanTotal))
			body.WriteString(fmt.Sprintf("TCP-проверки AD-портов: %d / %d (%d%%)\n", m.adScanDone, m.adScanTotal, percent))
			if job := m.jobByID(m.adScanJobID); job != nil && job.stage != "" {
				body.WriteString(job.stage + "\n")
			}
		} else {
			stage := "Подготовка диапазона…"
			if job := m.jobByID(m.adScanJobID); job != nil && job.stage != "" {
				stage = job.stage
			}
			body.WriteString(stage + "\n")
		}
		body.WriteString("Проверяются AD и Windows-порты, затем безопасные SMB/RDP-проверки и MS17-010; скорость — до 250 TCP-проверок/с. Лимита по числу адресов нет.\n")
		if len(m.adNetworks) > 0 && m.adNetworkIndex < len(m.adNetworks) {
			body.WriteString("Оценка для всей подсети: ~" + adscan.EstimateDuration(m.adNetworks[m.adNetworkIndex].CIDR).Round(time.Second).String() + "; фактическое время зависит от сети.\n")
		}
		body.WriteString("x или Esc — остановить.\n")
	}
	if m.adScanError != "" {
		body.WriteString("\n" + messageStyle.Render("Ошибка: "+m.adScanError) + "\n")
	}
	if m.adScanResult != nil {
		body.WriteString("\n" + headingStyle.Render("Результаты "+m.adScanResult.CIDR) + "\n")
		if len(m.adScanResult.Hosts) == 0 {
			body.WriteString("Открытые AD-порты не найдены.\n")
		} else {
			lo, hi := windowRange(m.serviceIndex, len(m.adScanResult.Hosts), max(1, m.panelRows()-12))
			body.WriteString(moreLine(lo, true))
			for i := lo; i < hi; i++ {
				controller := m.adScanResult.Hosts[i]
				title := controller.Address
				if controller.HostName != "" {
					title += "  " + controller.HostName
				}
				body.WriteString(headingStyle.Render(ansi.Truncate(title, max(12, w-8), "…")) + "\n")
				ports := make([]string, len(controller.Ports))
				for p, port := range controller.Ports {
					ports[p] = fmt.Sprint(port)
				}
				body.WriteString("  Роли: " + strings.Join(controller.Roles, ", ") + "\n")
				body.WriteString("  TCP: " + strings.Join(ports, ", ") + "\n")
				if controller.Domain != "" {
					body.WriteString("  Домен: " + controller.Domain + "\n")
				}
				if controller.LDAPMessage != "" {
					body.WriteString("  " + controller.LDAPMessage + "\n")
				}
			}
			body.WriteString(moreLine(len(m.adScanResult.Hosts)-hi, false))
		}
	}
	if m.message != "" {
		body.WriteString("\n" + messageStyle.Render(m.message) + "\n")
	}
	return m.renderPanel(w, body.String())
}
