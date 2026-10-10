package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/domain"
)

// openCredentials loads the current project's saved credentials (see
// internal/storage.Store.ListCredentials) and opens the list screen.
func (m *model) openCredentials() {
	if m.screen != "credentials" && m.screen != "input" && !strings.HasPrefix(m.screen, "cred-") {
		m.credentialsReturn = m.screen
	}

	creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
	if err != nil {
		m.message = "Не удалось загрузить credentials: " + err.Error()
		return
	}
	m.credentials = creds
	if m.credIndex >= len(m.credentials) {
		m.credIndex = max(0, len(m.credentials)-1)
	}
	m.screen = "credentials"
}

func (m model) updateCredentials(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q":
		if m.credentialsReturn == "ftp-setup" {
			return m.openFTPSetup()
		}
		if m.credentialsReturn == "smb-setup" {
			return m.openSMBCredentials()
		}
		if m.credentialsReturn == "mysql-setup" {
			return m.openMySQLSetup()
		}
		if m.credentialsReturn == "pg-setup" {
			return m.openPGSetup()
		}
		if m.credentialsReturn == "mssql-setup" {
			return m.openMSSQLSetup()
		}
		if m.credentialsReturn == "winrm-setup" {
			return m.openWinRMSetup()
		}
		m.screen = m.credentialsReturn
		if m.screen == "" {
			m.screen = "desk"
		}
		return m, nil
	case "up", "k":
		m.credIndex = max(0, m.credIndex-1)
	case "down", "j":
		m.credIndex = min(max(0, len(m.credentials)-1), m.credIndex+1)
	case "e", "enter":
		if m.credIndex >= 0 && m.credIndex < len(m.credentials) {
			c := m.credentials[m.credIndex]
			m.credEditID = c.ID
			m.credNewType, m.credNewUsername, m.credNewDomain, m.credNewSecret, m.credNewNotes = c.Type, c.Username, c.Domain, c.Secret, c.Notes
			m.screen = "cred-add-type"
		}
	case "a":
		m.credEditID, m.credNewNotes = 0, ""
		m.credNewType = "password"
		m.credNewUsername, m.credNewDomain, m.credNewSecret = "", "", ""
		m.screen = "cred-add-type"
	case "g":
		// nxc's `-u '' -p ''`: blank username/password is the anonymous/null
		// session identity itself, not a named credential type — one
		// keystroke here instead of confirming three empty prompts in a row.
		_, err := m.store.CreateCredential(m.ctx, domain.Credential{
			ProjectID: m.current.ID,
			Type:      "password",
			Notes:     "anonymous / null session",
		})
		if err != nil {
			m.message = "Не удалось сохранить credential: " + err.Error()
			return m, nil
		}
		m.openCredentials()
		m.credIndex = max(0, len(m.credentials)-1)
		m.message = "Anonymous-credential добавлен."
		return m, nil
	case "d":
		if m.credIndex < len(m.credentials) {
			m.credDeleteID = m.credentials[m.credIndex].ID
			m.screen = "cred-delete-confirm"
		}
	}
	return m, nil
}

func (m model) viewCredentials(w int) string {
	var body string
	body += headingStyle.Render("Credentials — "+m.current.Name) + "\n"
	body += "Учётные данные для post-auth проверок (spray / модули): никогда не передаются третьим сервисам, хранятся как есть (без шифрования).\n\n"
	if len(m.credentials) == 0 {
		body += "Пока ни одного credential. Нажми a, чтобы добавить.\n"
		return m.renderPanel(w, body)
	}
	lo, hi := windowRange(m.credIndex, len(m.credentials), m.panelRows())
	body += moreLine(lo, true)
	for i := lo; i < hi; i++ {
		c := m.credentials[i]
		ident := credIdentLabel(c)
		line := fmt.Sprintf("%-10s  %-28s  %s", credTypeLabel(c.Type), ident, c.Secret+"  "+c.Notes)
		body += renderListRow(line, i == m.credIndex, w)
	}
	body += moreLine(len(m.credentials)-hi, false)
	return m.renderPanel(w, body)
}

// credIdentLabel renders a credential's identity for list display — blank
// username/secret (nxc's `-u ” -p ”`) is the anonymous/null-session
// identity, not "nothing", so it gets a readable label instead of rendering
// as an empty cell.
func credIdentLabel(c domain.Credential) string {
	if c.Username == "" && c.Secret == "" {
		return "(anonymous / null session)"
	}
	ident := c.Username
	if c.Domain != "" {
		ident = c.Domain + `\` + c.Username
	}
	return ident
}

func credTypeLabel(t string) string {
	if t == "ntlm-hash" {
		return "NTLM-хеш"
	}
	return "пароль"
}

// --- add-credential wizard: type → username → domain → secret → notes ----

func (m model) updateCredAddType(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.screen = "credentials"
	case "left", "right", "tab", " ":
		if m.credNewType == "password" {
			m.credNewType = "ntlm-hash"
		} else {
			m.credNewType = "password"
		}
	case "enter":
		m.startInput("cred-username")
	}
	return m, nil
}

func (m model) viewCredAddType(w int) string {
	title := "Новый credential — тип секрета"
	if m.credEditID != 0 {
		title = "Редактирование учётки — тип секрета"
	}
	body := headingStyle.Render(title) + "\n\n"
	body += checkMark(m.credNewType == "password") + " пароль\n"
	body += checkMark(m.credNewType == "ntlm-hash") + " NTLM-хеш (pass-the-hash)\n\n"
	body += "←/→ переключить · Enter далее · Esc отмена"
	return m.renderPanel(w, body)
}

// saveCredential is cred-notes' terminal step — every prior field
// (type/username/domain/secret) is already collected in m.credNew*.
func (m model) saveCredential(notes string) (tea.Model, tea.Cmd) {
	m.screen = "credentials"
	c := domain.Credential{
		ID:        m.credEditID,
		ProjectID: m.current.ID,
		Type:      m.credNewType,
		Username:  m.credNewUsername,
		Domain:    m.credNewDomain,
		Secret:    m.credNewSecret,
		Notes:     notes,
	}
	editing := m.credEditID != 0
	var err error
	if editing {
		err = m.store.UpdateCredential(m.ctx, c)
	} else {
		_, err = m.store.CreateCredential(m.ctx, c)
	}
	m.credNewUsername, m.credNewDomain, m.credNewSecret = "", "", ""
	if err != nil {
		m.message = "Не удалось сохранить credential: " + err.Error()
		return m, nil
	}
	m.openCredentials()
	if editing {
		m.message = "Учётка обновлена."
	} else {
		m.credIndex = max(0, len(m.credentials)-1)
		m.message = "Credential добавлен."
	}
	m.credEditID, m.credNewNotes = 0, ""
	return m, nil
}

// --- delete confirm --------------------------------------------------

func (m model) updateCredDeleteConfirm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "n":
		m.screen = "credentials"
		return m, nil
	case "enter", "y":
		if err := m.store.DeleteCredential(m.ctx, m.credDeleteID); err != nil {
			m.message = "Не удалось удалить: " + err.Error()
			m.screen = "credentials"
			return m, nil
		}
		m.openCredentials()
		m.message = "Credential удалён."
		return m, nil
	}
	return m, nil
}

func (m model) viewCredDeleteConfirm(w int) string {
	return m.renderPanel(w, headingStyle.Render("Удалить credential?")+"\n\nЭто действие необратимо.\n\nEnter — удалить · Esc — отмена")
}
