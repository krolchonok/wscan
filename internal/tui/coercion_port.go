package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/adscan"
)

type coercePortChecked struct {
	generation int
	owners     []adscan.PortOwner
	err        error
}
type coercePortReleased struct {
	generation int
	lease      *adscan.PortLease
	err        error
}

func (m model) requestCoercionPort(action string) (tea.Model, tea.Cmd) {
	m.coercePortGeneration++
	generation := m.coercePortGeneration
	m.coercePortAction = action
	m.coercePortIP = m.adCoerceCallback
	m.coercePortReturn = m.screen
	m.screen = "coerce-port-check"
	m.coercePortOwners = nil
	ip := m.coercePortIP
	return m, func() tea.Msg {
		owners, err := adscan.CheckCoercionPort(ip)
		return coercePortChecked{generation: generation, owners: owners, err: err}
	}
}
func (m model) applyCoercionPortChecked(x coercePortChecked) (tea.Model, tea.Cmd) {
	if x.generation != m.coercePortGeneration || m.screen != "coerce-port-check" {
		return m, nil
	}
	if x.err != nil {
		m.screen = m.coercePortReturn
		m.message = "Не удалось подготовить порт 445: " + x.err.Error()
		return m, nil
	}
	m.coercePortOwners = x.owners
	if len(x.owners) > 0 {
		m.screen = "coerce-port-confirm"
		return m, nil
	}
	return m.continueCoercionPort()
}
func (m model) continueCoercionPort() (tea.Model, tea.Cmd) {
	m.screen = m.coercePortReturn
	m.coercePortApproved = true
	if m.coercePortAction == "responder" {
		return m.toggleResponder()
	}
	return m.startCoercion()
}
func (m model) updateCoercionPort(key string) (tea.Model, tea.Cmd) {
	if key == "esc" || key == "q" || key == "n" {
		if m.coercePortCancel != nil {
			m.coercePortCancel()
			m.coercePortCancel = nil
		}
		m.coercePortGeneration++
		m.screen = m.coercePortReturn
		m.message = "Запуск отменён; неподтверждённые процессы не завершались"
		return m, nil
	}
	if m.screen != "coerce-port-confirm" || (key != "enter" && key != "y") {
		return m, nil
	}
	parent := m.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	m.coercePortCancel = cancel
	generation, ip, owners := m.coercePortGeneration, m.coercePortIP, append([]adscan.PortOwner(nil), m.coercePortOwners...)
	m.screen = "coerce-port-stopping"
	return m, func() tea.Msg {
		defer cancel()
		lease, err := adscan.StopCoercionPortOwners(ctx, ip, owners)
		return coercePortReleased{generation: generation, lease: lease, err: err}
	}
}
func (m model) applyCoercionPortReleased(x coercePortReleased) (tea.Model, tea.Cmd) {
	if x.generation != m.coercePortGeneration || m.screen != "coerce-port-stopping" {
		if x.lease != nil {
			return m, func() tea.Msg { err := x.lease.Restore(); return coercePortRestored{err: err} }
		}
		return m, nil
	}
	m.coercePortCancel = nil
	if x.err != nil {
		m.screen = m.coercePortReturn
		m.message = "Не удалось освободить порт: " + x.err.Error()
		return m, nil
	}
	m.coercePortLease = x.lease
	m.message = "Порт 445 освобождён; запускаю приёмник…"
	return m.continueCoercionPort()
}

type coercePortRestored struct{ err error }

func (m model) viewCoercionPort(w int) string {
	body := headingStyle.Render("Подготовка Responder") + fmt.Sprintf("\n\nПриёмник: %s:445\n\n", m.coercePortIP)
	switch m.screen {
	case "coerce-port-check":
		body += "Проверяю, свободен ли порт…\nEsc — отменить"
	case "coerce-port-stopping":
		body += "Останавливаю подтверждённых владельцев порта…\nEsc — отменить запуск"
	default:
		body += "Порт занят:\n"
		for _, owner := range m.coercePortOwners {
			body += fmt.Sprintf("  PID %d · %q\n", owner.PID, owner.Name)
		}
		body += "\nОсвободить порт и запустить Responder?\n\n"
		samba := false
		other := false
		for _, owner := range m.coercePortOwners {
			if owner.Service == "smbd" {
				samba = true
			} else {
				other = true
			}
		}
		if samba {
			body += "Samba будет остановлена и восстановлена после остановки приёмника или выхода из программы.\n"
		}
		if other {
			body += "Другие перечисленные процессы получат SIGTERM; их автоматического перезапуска нет.\n"
		}
		body += "\nEnter / y — остановить и продолжить\nEsc / n — отменить"
	}
	return m.renderPanel(w, body)
}
