package tui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"strconv"
	"wscan/internal/domain"
)

type speedPreset struct {
	name         string
	rps, workers int
}

var speedPresets = []speedPreset{
	{"Минимальный", 5, 4},
	{"Средний", 50, 16},
	{"Максимальный", 200, 64},
	{"Без ограничений RPS", 0, 128},
}

var portSpeedPresets = []speedPreset{
	{"Минимальный", 100, 32}, {"Средний", 1000, 256},
	{"Максимальный", 10000, 1024}, {"Без ограничений RPS", 0, 2048},
}

func cycleSpeed(p domain.Project, ports bool, key string) domain.Project {
	presets := speedPresets
	rps, workers := p.RPS, p.Concurrency
	if ports {
		presets = portSpeedPresets
		rps, workers = p.DiscoveryRPS, p.DiscoveryConcurrency
	}
	index := -1
	for i, preset := range presets {
		if preset.rps == rps && preset.workers == workers {
			index = i
			break
		}
	}
	if index < 0 {
		if key == "left" {
			index = len(presets) - 1
		} else {
			index = 0
		}
	} else if key == "left" {
		index = (index + len(presets) - 1) % len(presets)
	} else {
		index = (index + 1) % len(presets)
	}
	preset := presets[index]
	if ports {
		p.DiscoveryRPS, p.DiscoveryConcurrency = preset.rps, preset.workers
	} else {
		p.RPS, p.Concurrency = preset.rps, preset.workers
	}
	return p
}

func portSpeedName(p domain.Project) string {
	for _, preset := range portSpeedPresets {
		if p.DiscoveryRPS == preset.rps && p.DiscoveryConcurrency == preset.workers {
			return preset.name
		}
	}
	return "Вручную"
}
func (m model) activeSpeedPresets() []speedPreset {
	if m.speedPorts {
		return portSpeedPresets
	}
	return speedPresets
}

func speedName(p domain.Project) string {
	for _, preset := range speedPresets {
		if p.RPS == preset.rps && p.Concurrency == preset.workers {
			return preset.name
		}
	}
	return "Вручную"
}

func (m *model) openSpeedPresets() {
	m.speedReturn = m.screen
	m.speedPorts = m.screen == "disc-options" || (m.screen == "settings" && m.settingsIndex == 9)
	p := m.current
	if m.speedReturn == "scan-review" {
		p = m.scanReviewProject
	}
	if m.speedReturn == "disc-options" {
		p = m.discProject
	}
	if m.speedPorts {
		p.RPS, p.Concurrency = p.DiscoveryRPS, p.DiscoveryConcurrency
	}
	m.speedIndex = 0
	for i, preset := range m.activeSpeedPresets() {
		if p.RPS == preset.rps && p.Concurrency == preset.workers {
			m.speedIndex = i
		}
	}
	m.screen = "speed-presets"
}

func (m model) updateSpeedPresets(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.screen = m.speedReturn
	case "up", "k", "left":
		m.speedIndex = max(0, m.speedIndex-1)
	case "down", "j", "right":
		m.speedIndex = min(len(m.activeSpeedPresets())-1, m.speedIndex+1)
	case "enter":
		preset := m.activeSpeedPresets()[m.speedIndex]
		m.screen = m.speedReturn
		if m.speedReturn == "disc-options" {
			m.discProject.DiscoveryRPS, m.discProject.DiscoveryConcurrency = preset.rps, preset.workers
			m.message = "Скорость портов для этого запуска: " + preset.name
		} else if m.speedReturn == "scan-review" {
			m.scanReviewProject.RPS, m.scanReviewProject.Concurrency = preset.rps, preset.workers
			m.message = "Скорость для этого запуска: " + preset.name
		} else {
			p := m.current
			if m.speedPorts {
				p.DiscoveryRPS, p.DiscoveryConcurrency = preset.rps, preset.workers
			} else {
				p.RPS, p.Concurrency = preset.rps, preset.workers
			}
			return m.persistSettings(p)
		}
	}
	return m, nil
}

func (m model) viewSpeedPresets(w int) string {
	title := "Скорость проверок"
	if m.speedPorts {
		title = "Скорость поиска портов"
	}
	body := headingStyle.Render(title) + "\n\n"
	for i, preset := range m.activeSpeedPresets() {
		rate := fmt.Sprintf("%d запросов/с", preset.rps)
		if m.speedPorts {
			rate = fmt.Sprintf("%d проб/с", preset.rps)
		}
		if preset.rps == 0 {
			rate = "без лимита скорости"
		}
		body += renderListRow(fmt.Sprintf("%s · %s · %d параллельно", preset.name, rate, preset.workers), i == m.speedIndex, w-4)
	}
	if m.speedPorts {
		body += "\nСкорость — портовые пробы в секунду на хост.\nБез лимита RPS: TCP до 2048 параллельно, UDP до 256.\nПресет сохраняет выбор портов, TCP/UDP и версий.\n"
		return m.renderPanel(w, body)
	}
	body += "\nПресет меняет RPS и параллельность проверок.\nТаймаут, повторы и категории выбираются отдельно.\nБез ограничений RPS: нет задержки по скорости;\nпараллельность остаётся 128 и доступна для изменения.\n"
	return m.renderPanel(w, body)
}

func (m model) saveDiscSettingValue(value string) (tea.Model, tea.Cmd) {
	m.screen = "disc-options"
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || (m.discOptIndex == 7 && (n < 1 || n > 2048)) {
		m.message = "Скорость: целое число от 0; параллельность: 1–2048."
		return m, nil
	}
	if m.discOptIndex == 6 {
		m.discProject.DiscoveryRPS = n
	} else {
		m.discProject.DiscoveryConcurrency = n
	}
	m.message = "Параметр изменён только для этого запуска."
	return m, nil
}
