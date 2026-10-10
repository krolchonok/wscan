package tui

import (
	"encoding/json"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

// openSpraySetup opens the credential picker for a credential-attack
// (SprayCredentials) against one specific target service — see the 'x' key
// on the desk (updateDesk). Deliberately single-target, not a bulk
// multi-host flow: nxc-style spraying across many hosts at once is exactly
// the scenario the lockout-safety accounting in internal/storage exists to
// protect against, and a one-target-at-a-time TUI flow keeps that blast
// radius visible and intentional rather than a single keystroke away.
func (m *model) openSpraySetup(svc domain.Service) {
	if !m.current.AllowCredentialAttack {
		m.message = "Credential-атаки выключены в настройках проекта (p)."
		return
	}
	creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
	if err != nil {
		m.message = "Не удалось загрузить credentials: " + err.Error()
		return
	}
	if len(creds) == 0 {
		m.message = "Сначала добавь credentials (клавиша c)."
		return
	}
	m.sprayTarget = &svc
	m.sprayCredentials = creds
	m.sprayChecked = map[int64]bool{}
	m.sprayCredIndex = 0
	m.screen = "spray-setup"
}

func (m model) updateSpraySetup(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.screen = "desk"
	case "up", "k":
		m.sprayCredIndex = max(0, m.sprayCredIndex-1)
	case "down", "j":
		m.sprayCredIndex = min(max(0, len(m.sprayCredentials)-1), m.sprayCredIndex+1)
	case " ", "space":
		if m.sprayCredIndex < len(m.sprayCredentials) {
			id := m.sprayCredentials[m.sprayCredIndex].ID
			m.sprayChecked[id] = !m.sprayChecked[id]
		}
	case "a":
		for _, c := range m.sprayCredentials {
			m.sprayChecked[c.ID] = true
		}
	case "n":
		m.sprayChecked = map[int64]bool{}
	case "enter":
		selected := m.selectedSprayCredentials()
		if len(selected) == 0 {
			m.message = "Отметь хотя бы один credential (Space)."
			return m, nil
		}
		m.spraySelectedCreds = selected
		m.screen = "spray-running"
		return m, m.runSprayCmd(selected)
	}
	return m, nil
}

func (m model) selectedSprayCredentials() []domain.Credential {
	var out []domain.Credential
	for _, c := range m.sprayCredentials {
		if m.sprayChecked[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

func (m model) viewSpraySetup(w int) string {
	t := m.sprayTarget
	body := headingStyle.Render(fmt.Sprintf("Credential-атака — %s:%d/%s", t.Host, t.Port, t.Protocol)) + "\n"
	body += "Отметь credentials для проверки (Space), затем Enter — запуск.\n\n"
	for i, c := range m.sprayCredentials {
		line := checkMark(m.sprayChecked[c.ID]) + " " + credTypeLabel(c.Type) + "  " + credIdentLabel(c)
		body += renderListRow(line, i == m.sprayCredIndex, w)
	}
	return m.renderPanel(w, body)
}

// sprayDone carries SprayCredentials' result back into Update — see
// runSprayCmd. Modeled on syncDone/templateDone (tui.go): a plain tea.Cmd
// that runs synchronously and reports back with a message, not the
// background-job machinery in jobs.go, which is built around
// engine.Result's Findings/Services shape and doesn't fit AuthAttempt rows.
type sprayDone struct {
	results []domain.AuthAttempt
	err     error
}

func (m model) runSprayCmd(creds []domain.Credential) tea.Cmd {
	p := m.current
	target := *m.sprayTarget
	scanner := m.scanner
	ctx := m.ctx
	return func() tea.Msg {
		res, err := scanner.SprayCredentials(ctx, p, []domain.Service{target}, creds)
		if res == nil {
			return sprayDone{err: err}
		}
		return sprayDone{results: res.Attempts, err: err}
	}
}

func (m model) viewSprayRunning(w int) string {
	return m.renderPanel(w, headingStyle.Render("Credential-атака")+"\n\nВыполняется…")
}

func (m model) updateSprayResults(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.screen = "desk"
	case "up", "k":
		m.sprayResultIndex = max(0, m.sprayResultIndex-1)
	case "down", "j":
		m.sprayResultIndex = min(max(0, len(m.sprayResults)-1), m.sprayResultIndex+1)
	case "m":
		if m.sprayResultIndex < len(m.sprayResults) {
			a := m.sprayResults[m.sprayResultIndex]
			if !a.Success {
				m.message = "Модули доступны только для успешных попыток."
				return m, nil
			}
			m.openModulePicker(a)
		}
	}
	return m, nil
}

func attemptStatus(a domain.AuthAttempt) string {
	switch {
	case a.Skipped:
		return "⊘ пропущено (лок-аут)"
	case a.Success:
		return "✓ успех"
	case a.Error != "":
		return "✗ " + a.Error
	default:
		return "✗ неверный credential"
	}
}

func (m model) viewSprayResults(w int) string {
	body := headingStyle.Render("Результат credential-атаки") + "\n\n"
	if len(m.sprayResults) == 0 {
		body += "Нет результатов.\n"
		return m.renderPanel(w, body)
	}
	lo, hi := windowRange(m.sprayResultIndex, len(m.sprayResults), m.panelRows())
	body += moreLine(lo, true)
	for i := lo; i < hi; i++ {
		a := m.sprayResults[i]
		ident := a.Username
		switch {
		case a.Username == "":
			ident = "(anonymous / null session)"
		case a.Domain != "":
			ident = a.Domain + `\` + a.Username
		}
		line := fmt.Sprintf("%-28s  %s", ident, attemptStatus(a))
		body += renderListRow(line, i == m.sprayResultIndex, w)
	}
	body += moreLine(len(m.sprayResults)-hi, false)
	return m.renderPanel(w, body)
}

// --- post-auth module picker / runner -------------------------------

func (m *model) openModulePicker(a domain.AuthAttempt) {
	mods := engine.AvailableModules(a.Protocol)
	if len(mods) == 0 {
		m.message = "Для этого протокола пока нет модулей."
		return
	}
	m.sprayModuleAttempt = &a
	m.sprayModules = mods
	m.sprayModuleIndex = 0
	m.screen = "spray-module-picker"
}

func (m model) updateSprayModulePicker(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		m.screen = "spray-results"
	case "up", "k":
		m.sprayModuleIndex = max(0, m.sprayModuleIndex-1)
	case "down", "j":
		m.sprayModuleIndex = min(max(0, len(m.sprayModules)-1), m.sprayModuleIndex+1)
	case "enter":
		if m.sprayModuleIndex >= len(m.sprayModules) {
			return m, nil
		}
		mod := m.sprayModules[m.sprayModuleIndex]
		if mod.Name == "smb-configs" {
			m.startInput("module-share")
			return m, nil
		}
		if mod.Name == "winrm-exec" {
			m.startInput("module-command")
			return m, nil
		}
		return m.runSelectedModule(nil)
	}
	return m, nil
}

func (m model) viewSprayModulePicker(w int) string {
	body := headingStyle.Render("Post-auth модуль") + "\n\n"
	for i, mod := range m.sprayModules {
		line := fmt.Sprintf("%-32s  %s", mod.Name, mod.Description)
		body += renderListRow(line, i == m.sprayModuleIndex, w)
	}
	return m.renderPanel(w, body)
}

// runSelectedModule finds the credential behind the attempt the module
// picker was opened for (AuthAttempt never carries Secret — results must
// stay safe to log/display) and launches RunModule with it.
func (m model) runSelectedModule(args map[string]string) (tea.Model, tea.Cmd) {
	if m.sprayModuleAttempt == nil || m.sprayModuleIndex >= len(m.sprayModules) {
		m.screen = "spray-results"
		return m, nil
	}
	cred, ok := m.credentialForAttempt(*m.sprayModuleAttempt)
	if !ok {
		m.message = "Не удалось сопоставить credential для этой попытки."
		m.screen = "spray-results"
		return m, nil
	}
	mod := m.sprayModules[m.sprayModuleIndex]
	m.sprayModuleArgs = args
	m.screen = "spray-running"
	return m, m.runModuleCmd(cred, *m.sprayTarget, mod.Name, args)
}

func (m model) credentialForAttempt(a domain.AuthAttempt) (domain.Credential, bool) {
	for _, c := range m.spraySelectedCreds {
		if c.Username == a.Username && c.Domain == a.Domain {
			return c, true
		}
	}
	return domain.Credential{}, false
}

type moduleDone struct {
	result *domain.ModuleResult
	err    error
}

func (m model) runModuleCmd(cred domain.Credential, target domain.Service, name string, args map[string]string) tea.Cmd {
	p := m.current
	scanner := m.scanner
	ctx := m.ctx
	return func() tea.Msg {
		res, err := scanner.RunModule(ctx, p, target, cred, name, args)
		return moduleDone{result: res, err: err}
	}
}

func (m model) updateSprayModuleResult(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q", "enter":
		m.screen = "spray-results"
	}
	return m, nil
}

func (m model) viewSprayModuleResult(w int) string {
	if m.sprayModuleResult == nil {
		return m.renderPanel(w, headingStyle.Render("Результат модуля")+"\n\nНет данных.")
	}
	r := m.sprayModuleResult
	body := headingStyle.Render("Результат модуля: "+r.Module) + "\n\n"
	if r.Error != "" {
		body += "Ошибка: " + r.Error + "\n"
		return m.renderPanel(w, body)
	}
	pretty, err := json.MarshalIndent(r.Data, "", "  ")
	if err != nil {
		body += fmt.Sprintf("%+v\n", r.Data)
	} else {
		body += string(pretty) + "\n"
	}
	return m.renderPanel(w, body)
}
