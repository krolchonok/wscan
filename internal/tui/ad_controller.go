package tui

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/discovery"
)

func (m *model) loadADControllerSelection() {
	m.adAccessManualHost = ""
	if m.current.ID == 0 {
		return
	}
	host, realm, err := m.store.ADController(m.ctx, m.current.ID)
	if err != nil {
		m.message = "Не удалось загрузить контроллер: " + err.Error()
		return
	}
	if host != "" {
		m.adAccessManualHost, m.adAccessHost, m.adAccessDomain = host, host, realm
		m.adAccessLDAPPort = 389
	}
}

// The picker includes all individual project machines, not just inferred DCs.
func (m model) adControllerHosts() []string {
	seen := map[string]bool{}
	for _, target := range m.interactionHosts() {
		if !discovery.IsNetworkTarget(target) {
			if host, err := discovery.TargetHost(target); err == nil && host != "" {
				seen[host] = true
			}
		}
	}
	for _, target := range m.current.Targets {
		if discovery.IsNetworkTarget(target) {
			continue
		}
		if host, err := discovery.TargetHost(target); err == nil && host != "" {
			seen[host] = true
		}
	}
	if m.adAccessManualHost != "" {
		seen[m.adAccessManualHost] = true
	}
	var hosts []string
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool {
		a, b := net.ParseIP(hosts[i]), net.ParseIP(hosts[j])
		if (a != nil) != (b != nil) {
			return a != nil
		}
		if a != nil && b != nil {
			return bytes.Compare(a.To16(), b.To16()) < 0
		}
		return hosts[i] < hosts[j]
	})
	return hosts
}

func (m *model) openADControllerPicker() {
	m.adAccessGeneration++
	if m.adAccessAutoBusy {
		m.adAccessHint = ""
	}
	m.adAccessAutoBusy = false
	m.adControllerReturn, m.screen = m.screen, "ad-controller-picker"
	m.adControllerIndex = 0
	for i, host := range m.adControllerHosts() {
		if host == m.adAccessHost {
			m.adControllerIndex = i + 1
			break
		}
	}
}

func (m *model) setADController(host string) error {
	if m.current.ID == 0 {
		return fmt.Errorf("сначала открой проект")
	}
	host = strings.TrimSpace(host)
	if strings.ContainsAny(host, "/\\ \t\r\n") {
		return fmt.Errorf("укажи один IP или DNS-хост контроллера")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Errorf("контроллер указывается без порта")
	}
	realm := ""
	if host == m.adAccessManualHost {
		realm = m.adAccessDomain
	}
	nodes := m.projectADInventory().Hosts
	if m.adAccessNodesProject == m.current.ID {
		nodes = append(nodes, m.adAccessNodes...)
	}
	for _, node := range nodes {
		if realm == "" && node.Address == host && node.Domain != "" {
			realm = node.Domain
		}
	}
	if err := m.store.SetADController(m.ctx, m.current.ID, host, realm); err != nil {
		return err
	}
	m.adAccessGeneration++
	m.adAccessAutoBusy, m.adAccessHint = false, ""
	m.adAccessManualHost, m.adAccessHost, m.adAccessDomain = host, host, realm
	m.adAccessAutoHost = ""
	m.adAccessLDAPPort, m.adBloodHoundPort = 389, 389
	m.chooseADAccessIdentity(nodes)
	if host != "" {
		m.message = "Контроллер выбран вручную: " + host
	} else {
		m.message = "Контроллер: автоопределение"
	}
	return nil
}

func (m model) updateADControllerPicker(key string) (tea.Model, tea.Cmd) {
	hosts := m.adControllerHosts()
	last := len(hosts) + 2
	m.adControllerIndex = min(m.adControllerIndex, last)
	switch key {
	case "up":
		m.adControllerIndex = max(0, m.adControllerIndex-1)
	case "down":
		m.adControllerIndex = min(last, m.adControllerIndex+1)
	case "home":
		m.adControllerIndex = 0
	case "end":
		m.adControllerIndex = last
	case "pgup":
		m.adControllerIndex = max(0, m.adControllerIndex-max(1, m.bodyHeight()-5))
	case "pgdown":
		m.adControllerIndex = min(last, m.adControllerIndex+max(1, m.bodyHeight()-5))
	case "left", "esc":
		m.screen = m.adControllerReturn
	case "enter":
		if m.adControllerIndex == last {
			m.screen = m.adControllerReturn
			return m, nil
		}
		if m.adControllerIndex == len(hosts)+1 {
			m.screen = m.adControllerReturn
			m.startInput("ad-access-host")
			m.input = m.adAccessHost
			return m, nil
		}
		host := ""
		if m.adControllerIndex > 0 {
			host = hosts[m.adControllerIndex-1]
		}
		if err := m.setADController(host); err != nil {
			m.message = err.Error()
			return m, nil
		}
		m.screen = m.adControllerReturn
		return m, m.detectADAccessIdentityCmd()
	}
	return m, nil
}

func (m model) viewADControllerPicker(w int) string {
	hosts := m.adControllerHosts()
	rows := []string{"Автоопределение контроллера"}
	names := map[string]string{}
	for _, host := range m.projectADInventory().Hosts {
		if host.HostName != "" {
			names[host.Address] = host.HostName
		}
	}
	for _, host := range hosts {
		label := host
		name := names[host]
		if name == "" && len(m.hostNames[host]) > 0 {
			name = m.hostNames[host][0]
		}
		if name != "" && name != host {
			label += " · " + name
		}
		if host == m.adAccessManualHost {
			label += " · DC (вручную)"
		}
		rows = append(rows, label)
	}
	rows = append(rows, "Ввести IP/DNS вручную…", "Назад")
	body := headingStyle.Render("Контроллер домена") + "\n\n"
	index := min(m.adControllerIndex, len(rows)-1)
	lo, hi := windowRange(index, len(rows), max(1, m.bodyHeight()-5))
	body += moreLine(lo, true)
	for i := lo; i < hi; i++ {
		body += renderListRow(rows[i], i == index, w-4)
	}
	body += moreLine(len(rows)-hi, false)
	return m.renderPanel(w, body)
}
