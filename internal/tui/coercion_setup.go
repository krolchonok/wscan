package tui

import (
	"context"
	"fmt"
	"net"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

const interactionCoerceIndex = 16

type coerceRouteReady struct {
	host, ip string
	err      error
}

func (m model) openHostCoercion() (tea.Model, tea.Cmd) {
	host := m.smbBrowser.host
	if host == "" {
		m.message = "Выбери машину (h)"
		return m, nil
	}
	m.openADAccess()
	m.screen = "coerce-setup"
	m.adAccessHost = host
	m.adAccessIndex = 1
	m.coerceActionIndex = 0
	if len(m.adAccessCreds) == 1 {
		m.adAccessCred = 0
		m.adAccessDomain = m.adAccessCreds[0].Domain
	}
	if m.adCoerceCallback == "" || m.coerceCallbackAuto {
		m.adCoerceCallback = ""
		m.coerceCallbackAuto = true
		return m, m.coerceRouteCmd(host)
	}
	return m, nil
}
func (m model) coerceRouteCmd(host string) tea.Cmd {
	parent := m.ctx
	if parent == nil {
		parent = context.Background()
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(parent, 2*time.Second)
		defer cancel()
		ip, err := localCoercionAddress(ctx, host)
		return coerceRouteReady{host: host, ip: ip, err: err}
	}
}
func localCoercionAddress(ctx context.Context, host string) (string, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	for _, a := range addresses {
		if a.IP.To4() == nil {
			continue
		}
		// UDP connect selects the OS route and source address without sending data.
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", net.JoinHostPort(a.IP.String(), "445"))
		if err != nil {
			return "", err
		}
		defer conn.Close()
		source := conn.LocalAddr().(*net.UDPAddr).IP
		if source == nil || source.IsUnspecified() {
			return "", fmt.Errorf("маршрут не определил локальный адрес")
		}
		return source.String(), nil
	}
	return "", fmt.Errorf("у цели нет IPv4 адреса")
}
func (m model) applyCoerceRoute(x coerceRouteReady) (tea.Model, tea.Cmd) {
	if x.host != m.adAccessHost || !m.coerceCallbackAuto {
		return m, nil
	}
	if x.err != nil {
		m.message = "Не удалось выбрать адрес приёмника: " + x.err.Error() + " · r указать вручную"
		return m, nil
	}
	m.adCoerceCallback = x.ip
	if m.screen == "coerce-setup" {
		m.message = "Приёмник на этой машине: " + x.ip + " · Enter — запустить Responder"
	}
	return m, nil
}
func (m model) updateCoercionSetup(key string) (tea.Model, tea.Cmd) {
	if m.adAccessJobRunning() {
		if key == "esc" || key == "q" {
			if j := m.jobByID(m.adAccessJobID); j != nil && j.cancel != nil {
				j.cancel()
			}
			m.message = "Останавливаю Coerce; сохраняю результаты…"
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		m.screen = m.adAccessReturn
	case "up", "k":
		m.coerceActionIndex = (m.coerceActionIndex + 4) % 5
	case "down", "j", "tab":
		m.coerceActionIndex = (m.coerceActionIndex + 1) % 5
	case "r":
		m.startInput("ad-coerce-callback")
	case "d":
		m.startInput("ad-access-domain")
	case "c":
		return m.updateADAccess("c")
	case "p":
		return m.toggleResponder()
	case "enter":
		switch m.coerceActionIndex {
		case 0:
			return m.toggleResponder()
		case 1:
			m.adAccessIndex = 1
			return m.startCoercion()
		case 2:
			m.adAccessIndex = 0
			return m.startCoercion()
		case 3:
			return m.updateADAccess("c")
		case 4:
			m.startInput("ad-coerce-callback")
		}
	}
	return m, nil
}
func (m model) viewCoercionSetup(w int) string {
	cred := "не выбрана · обычно требуется для RPC (c)"
	if m.adAccessCred >= 0 && m.adAccessCred < len(m.adAccessCreds) {
		cred = credIdentLabel(m.adAccessCreds[m.adAccessCred])
	}
	receiver := valueOr(m.adCoerceCallback, "определяю локальный адрес…")
	origin := "вручную"
	if m.coerceCallbackAuto {
		origin = "эта машина, адрес по маршруту к цели"
	}
	body := headingStyle.Render("Coerce / Responder") + fmt.Sprintf("\n\nЦель: %s · TCP/445\nПриёмник: %s:445 · %s · r изменить\nУчётка: %s\nДомен учётки: %s · d изменить (для локальной можно оставить пустым)\nResponder: %s\n\n", m.adAccessHost, receiver, origin, cred, valueOr(m.adAccessDomain, "не задан"), m.responderStatus())
	responderAction := "Запустить Responder на этой машине"
	if j := m.jobByID(m.adResponderJobID); j != nil && j.status == statusRunning {
		responderAction = "Остановить Responder и сохранить события"
	}
	rows := []string{responderAction, "Проверить Coerce (приёмник включится автоматически, если не запущен)", "Проверить доступность RPC без Coerce", "Выбрать учётку", "Изменить адрес приёмника"}
	for i, row := range rows {
		body += renderListRow(row, i == m.coerceActionIndex, w)
	}
	body += "\n↑/↓ — действие · Enter — выполнить · c — учётка · p — Responder · Esc — назад/отменить\n"
	if m.adAccessJobRunning() {
		if j := m.jobByID(m.adAccessJobID); j != nil {
			body += "\nПроверка: " + j.stage + "\n"
		}
	} else if m.responderStatus() == "остановлен" {
		body += "\nСначала можно запустить Responder и наблюдать события, затем проверить машину.\n"
	}
	body += "NTLM negotiate — начало обмена; anonymous-authenticate — ответ без учётных данных; ntlm-authenticate — непустой ответ, криптографически не проверен. Отказ во входе не означает защищённость. Результаты — в «5 Результаты»."
	return m.renderPanel(w, body)
}
