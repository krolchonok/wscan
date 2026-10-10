package tui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"strings"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/storage"
)

type inventoryExclusion = storage.InventoryExclusion

func portResultPolicy(known bool) string {
	if known {
		return "открытые с определённым сервисом"
	}
	return "все открытые, включая неизвестный сервис"
}

func (m *model) requestDelete() {
	m.deleteNetwork = ""
	m.deleteHost = m.currentHost()
	m.deleteService = nil
	if m.deleteHost == "" {
		m.message = "Выбери конкретный хост или порт."
		return
	}
	if m.focusCol > 0 {
		services := m.servicesFor(m.deleteHost)
		if m.serviceIndex < 0 || m.serviceIndex >= len(services) {
			m.message = "Выбери конкретный порт."
			return
		}
		s := services[m.serviceIndex]
		m.deleteService = &s
	}
	m.screen = "delete-confirm"
}

func (m model) updateDelete(key string) (tea.Model, tea.Cmd) {
	if key == "esc" || key == "n" {
		if m.deleteNetwork != "" {
			m.screen = "networks"
			m.deleteNetwork = ""
		} else {
			m.screen = "desk"
		}
		return m, nil
	}
	if key != "enter" && key != "y" {
		return m, nil
	}
	if m.deleteNetwork != "" {
		network := m.deleteNetwork
		m.deleteNetwork = ""
		if err := m.store.RemoveTarget(m.ctx, m.current.ID, network); err != nil {
			m.message = err.Error()
		} else {
			delete(m.selectedNetworks, network)
			_ = m.reload()
			m.current = m.findProject(m.current.ID)
			if m.hostNetwork == network {
				m.hostNetwork = ""
			}
			m.rebuildHostOrder()
			m.networkIndex = min(m.networkIndex, max(0, len(m.networkTargets())-1))
			m.message = "Подсеть удалена из проекта: " + network
		}
		m.screen = "networks"
		return m, nil
	}
	var targets []string
	service := ""
	if m.deleteService != nil {
		service = serviceKey(*m.deleteService)
	} else {
		for _, target := range m.current.Targets {
			host, err := discovery.TargetHost(target)
			if err == nil && host == m.deleteHost {
				targets = append(targets, target)
			}
		}
	}
	aliases := []string{m.deleteHost}
	if m.deleteService == nil {
		for _, s := range m.servicesFor(m.deleteHost) {
			aliases = append(aliases, s.Host)
		}
	}
	if err := m.store.ExcludeInventory(m.ctx, m.current.ID, m.deleteHost, service, targets, uniqueStrings(aliases)); err != nil {
		m.message = err.Error()
		return m, nil
	}
	m.exclusions = append(m.exclusions, inventoryExclusion{Host: m.deleteHost, ServiceKey: service})
	_ = m.reload()
	m.current = m.findProject(m.current.ID)
	if m.deleteService == nil {
		for _, j := range m.jobs {
			if j.projectID != m.current.ID || !j.active() {
				continue
			}
			for _, target := range j.targets {
				host, _ := discovery.TargetHost(target)
				if host == m.deleteHost {
					j.cancel()
					break
				}
			}
		}
		m.inventoryResets, _ = m.store.InventoryResets(m.ctx, m.current.ID)
		m.history, _ = m.store.Runs(m.ctx, m.current.ID)
	}
	m.filterInventory()
	m.rebuildHostOrder()
	m.serviceIndex, m.findingIndex = 0, 0
	m.screen = "desk"
	m.message = "Порт удалён из рабочего списка."
	if m.deleteService == nil {
		m.message = "Хост удалён. При повторном добавлении порты и находки будут пустыми."
	}
	return m, nil
}

func (m model) viewDelete(w int) string {
	if m.deleteNetwork != "" {
		return m.renderPanel(w, headingStyle.Render("Удалить подсеть?")+"\n\n"+m.deleteNetwork+"\n\nБудет удалён диапазон из проекта. Уже найденные хосты останутся в окне «Хосты».\n\nEnter — удалить · Esc — отмена")
	}
	label := "хост " + m.deleteHost
	if m.deleteService != nil {
		s := m.deleteService
		label = fmt.Sprintf("порт %s:%d/%s", s.Host, s.Port, s.Protocol)
	}
	detail := "Удаление порта из рабочего списка проекта."
	if m.deleteService == nil {
		detail = "Хост, его порты и находки удаляются из рабочего списка.\nСканы этого хоста будут остановлены.\nПовторное добавление — с чистого листа."
	}
	return m.renderPanel(w, headingStyle.Render("Удалить "+label+"?")+"\n\n"+detail+"\nИстория запусков сохраняется отдельно.\n\nEnter — удалить · Esc — отмена")
}

func (m model) beforeHostReset(host string, runID int64) bool {
	maxRun := m.maxInventoryRunID()
	for _, r := range m.inventoryResets {
		through := r.ThroughRun
		// Watermark past any known run means history was purged / ids reused —
		// ignore it so new scans are not invisible forever.
		if maxRun > 0 && through > maxRun {
			continue
		}
		if strings.EqualFold(r.Host, host) && runID <= through {
			return true
		}
	}
	return false
}

func (m model) findingBeforeReset(f domain.Finding, runID int64) bool {
	maxRun := m.maxInventoryRunID()
	for _, r := range m.inventoryResets {
		through := r.ThroughRun
		if maxRun > 0 && through > maxRun {
			continue
		}
		if runID > through {
			continue
		}
		for _, address := range []string{f.Target, f.MatchedAt} {
			host, err := discovery.TargetHost(address)
			if err != nil {
				continue
			}
			for _, alias := range r.Aliases {
				if strings.EqualFold(host, alias) {
					return true
				}
			}
		}
	}
	return false
}

func (m model) maxInventoryRunID() int64 {
	var max int64
	for _, r := range m.history {
		if r.ID > max {
			max = r.ID
		}
	}
	return max
}

func (m *model) filterInventory() {
	for _, e := range m.exclusions {
		if e.ServiceKey == "" {
			delete(m.inventory, e.Host)
			continue
		}
		hi := m.inventory[e.Host]
		if hi == nil {
			continue
		}
		filtered := hi.services[:0]
		for _, s := range hi.services {
			if serviceKey(s) != e.ServiceKey {
				filtered = append(filtered, s)
			}
		}
		hi.services = filtered
	}
}

func (m model) excludedHost(host string) bool {
	for _, e := range m.exclusions {
		if e.ServiceKey == "" && strings.EqualFold(e.Host, host) {
			return true
		}
	}
	return false
}
