package tui

import (
	"context"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"strings"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

type sshDictionaryState struct {
	passwordLists     []sshPasswordList
	passwordListIndex int
	projectID         int64
	target            domain.Service
	options           engine.SSHDictionaryOptions
	generation, index int
	busy              bool
	cancel            context.CancelFunc
	rows              []engine.SSHDictionaryAttempt
}
type sshDictionaryProgress struct {
	generation int
	row        engine.SSHDictionaryAttempt
	events     <-chan engine.SSHDictionaryAttempt
}
type sshDictionaryDone struct {
	generation int
	result     engine.SSHDictionaryResult
	err        error
}
type sshDictionaryClosed struct{}

func waitSSHDictionary(events <-chan engine.SSHDictionaryAttempt, generation int) tea.Cmd {
	return func() tea.Msg {
		row, ok := <-events
		if !ok {
			return sshDictionaryClosed{}
		}
		return sshDictionaryProgress{generation, row, events}
	}
}
func (m model) openSSHDictionary() (tea.Model, tea.Cmd) {
	b := &m.sshDictionary
	if b.busy && b.projectID == m.current.ID {
		m.screen = "ssh-dictionary"
		return m, nil
	}
	if b.cancel != nil {
		b.cancel()
	}
	target := domain.Service{Host: m.smbBrowser.host, Port: 22, Name: "ssh", Protocol: "ssh"}
	for i, s := range m.servicesFor(m.currentHost()) {
		if s.Protocol != "udp" && (s.Port == 22 || strings.Contains(strings.ToLower(s.Name+" "+s.PortService), "ssh")) {
			target = s
			target.Protocol = "ssh"
			if m.focusCol >= 1 && i == m.serviceIndex {
				break
			}
		}
	}
	*b = sshDictionaryState{projectID: m.current.ID, target: target, generation: b.generation + 1, options: engine.SSHDictionaryOptions{Username: "root", Passwordlist: defaultSSHPasswordList(m.appDir), Delay: 0, RPS: 5, Concurrency: 4, Unlimited: true}}
	m.screen = "ssh-dictionary"
	m.message = ""
	return m, nil
}
func (m model) updateSSHDictionary(key string) (tea.Model, tea.Cmd) {
	b := &m.sshDictionary
	if b.busy {
		switch key {
		case "esc":
			b.cancel()
			m.message = "Останавливаю SSH-перебор…"
			return m, nil
		case "up", "k", "down", "j":
		default:
			return m, nil
		}
	}
	switch key {
	case "esc", "q":
		m.screen = "interaction-menu"
	case "u":
		m.startInput("ssh-dict-user")
		m.input = b.options.Username
	case "l":
		m.startInput("ssh-dict-users")
		m.input = b.options.Userlist
	case "p":
		return m.openSSHPasswordLists()
	case "f":
		m.startInput("ssh-dict-passwords")
		m.input = b.options.Passwordlist
	case "t":
		m.startInput("ssh-dict-port")
		m.input = fmt.Sprint(b.target.Port)
	case "b":
		b.options.Unlimited = !b.options.Unlimited
	case "r":
		m.startInput("ssh-dict-rps")
		m.input = fmt.Sprint(b.options.RPS)
	case "c":
		m.startInput("ssh-dict-workers")
		m.input = fmt.Sprint(b.options.Concurrency)
	case "d":
		m.startInput("ssh-dict-delay")
		m.input = fmt.Sprint(b.options.Delay.Milliseconds())
	case "s", "enter":
		return m.startSSHDictionary()
	case "up", "k":
		b.index = max(0, b.index-1)
	case "down", "j":
		b.index = min(max(0, len(b.rows)-1), b.index+1)
	case "a":
		if b.index < len(b.rows) && b.rows[b.index].Attempt.Success {
			row := b.rows[b.index]
			_, err := m.store.CreateCredential(m.ctx, domain.Credential{ProjectID: m.current.ID, Type: "password", Username: row.Attempt.Username, Secret: row.Password, Notes: "SSH " + b.target.Host})
			if err != nil {
				m.message = err.Error()
			} else {
				m.message = "Успешная учётка сохранена"
			}
		}
	}
	return m, nil
}
func (m model) startSSHDictionary() (tea.Model, tea.Cmd) {
	b := &m.sshDictionary
	if b.busy {
		return m, nil
	}
	if !m.current.AllowCredentialAttack {
		m.message = "Включи credential-атаки в настройках проекта (p на экране хостов)"
		return m, nil
	}
	if b.options.Passwordlist == "" {
		m.message = "p — укажи словарь паролей"
		return m, nil
	}
	ctx := m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	b.cancel = cancel
	b.busy = true
	b.generation++
	b.rows = nil
	b.index = 0
	generation, target, options, project := b.generation, b.target, b.options, m.current
	scanner := m.scanner
	if scanner == nil {
		scanner = engine.New(m.store, engine.Config{TimeoutSeconds: project.TimeoutSeconds})
	}
	events := make(chan engine.SSHDictionaryAttempt, 32)
	run := func() tea.Msg {
		defer cancel()
		defer close(events)
		result, err := scanner.SSHDictionary(ctx, project, target, options, func(row engine.SSHDictionaryAttempt) {
			select {
			case events <- row:
			case <-ctx.Done():
			}
		})
		return sshDictionaryDone{generation, result, err}
	}
	m.message = ""
	return m, tea.Batch(run, waitSSHDictionary(events, generation))
}
func (m model) applySSHDictionaryProgress(ev sshDictionaryProgress) (tea.Model, tea.Cmd) {
	b := &m.sshDictionary
	if b.generation == ev.generation && b.busy {
		b.rows = append(b.rows, ev.row)
		b.index = len(b.rows) - 1
	}
	return m, waitSSHDictionary(ev.events, ev.generation)
}
func (m model) applySSHDictionaryDone(done sshDictionaryDone) (tea.Model, tea.Cmd) {
	b := &m.sshDictionary
	if b.generation != done.generation {
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	b.rows = done.result.Attempts
	b.index = min(b.index, max(0, len(b.rows)-1))
	m.message = fmt.Sprintf("Попыток: %d · успехов: %d · достигли лимита: %d", done.result.Tried, done.result.Found, done.result.Blocked)
	if done.err != nil {
		m.message += " · " + done.err.Error()
	}
	return m, nil
}
func (m model) viewSSHDictionary(w int) string {
	b := m.sshDictionary
	maxAttempts, window := m.current.LockoutMaxAttempts, m.current.LockoutWindowMinutes
	if maxAttempts <= 0 {
		maxAttempts = domain.DefaultLockoutMaxAttempts
	}
	if window <= 0 {
		window = domain.DefaultLockoutWindowMinutes
	}
	limit := fmt.Sprintf("%d ошибок на пользователя за %d мин", maxAttempts, window)
	if b.options.Unlimited {
		limit = "без ограничения попыток"
	}
	body := headingStyle.Render("SSH — словарный перебор") + fmt.Sprintf("\n%s:%d · пользователь: %s\nПользователи: %s\nПароли: %s\nRPS: %d · потоки: %d · пауза: %s · лимит: %s\n", smbDisplayName(b.target.Host), b.target.Port, smbDisplayName(b.options.Username), smbDisplayName(b.options.Userlist), smbDisplayName(b.options.Passwordlist), b.options.RPS, b.options.Concurrency, b.options.Delay, limit)
	body += "u пользователь · l файл пользователей · p словарь паролей · f свой файл · t порт · r RPS · c потоки · d пауза (мс)\nb лимит проекта вкл/выкл · s запуск · a сохранить успешную учётку · Esc назад / остановить\n"
	lo, hi := windowRange(b.index, len(b.rows), max(1, m.panelRows()-10))
	for i := lo; i < hi; i++ {
		row := b.rows[i]
		line := row.Attempt.Username + " · " + sshDictionaryAttemptStatus(row.Attempt)
		if row.Cancelled {
			line = row.Attempt.Username + " · ⏹ остановлено после успеха"
		}
		if !row.Attempt.Skipped {
			line += fmt.Sprintf(" · пароль: %q", row.Password)
		}
		body += renderListRow(sanitizeWinRMText(line), i == b.index, w)
	}
	if b.busy {
		body += "\nВыполняется…"
	}
	return m.renderPanel(w, body)
}

func sshDictionaryAttemptStatus(a domain.AuthAttempt) string {
	lower := strings.ToLower(a.Error)
	if !a.Success && !a.Skipped && (strings.Contains(lower, "unable to authenticate") || strings.Contains(lower, "no supported methods remain") || strings.Contains(lower, "permission denied")) {
		return "✗ пароль не подошёл"
	}
	return attemptStatus(a)
}
