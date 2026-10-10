package tui

import (
	"context"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"time"
	"wscan/internal/domain"
	"wscan/internal/engine/js"
)

func (b smbBrowserState) options() js.SMBBrowseOptions {
	return js.SMBBrowseOptions{Host: b.host, Port: b.port, Mode: b.mode, Credential: b.credential}
}
func (m model) openSMBCredentials() (tea.Model, tea.Cmd) {
	creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
	if err != nil {
		m.message = err.Error()
		return m, nil
	}
	m.smbBrowser.credentials = creds
	m.smbBrowser.credIndex = 0
	m.screen = "smb-setup"
	return m, nil
}
func (m model) updateSMBCredentials(key string) (tea.Model, tea.Cmd) {
	b := &m.smbBrowser
	if b.busy {
		if key == "esc" {
			b.cancel()
			b.generation++
			b.busy = false
			m.message = "Вход SMB отменён"
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		m.screen = "smb-browser"
	case "up", "k":
		b.credIndex = max(0, b.credIndex-1)
	case "down", "j":
		b.credIndex = min(max(0, len(b.credentials)-1), b.credIndex+1)
	case "c":
		m.openCredentials()
	case "enter":
		if b.credIndex >= len(b.credentials) {
			m.message = "c → a: добавь учётку"
			return m, nil
		}
		cred := b.credentials[b.credIndex]
		if cred.Type != "password" && cred.Type != "ntlm-hash" {
			m.message = "SMB: нужен пароль или NTLM-хеш"
			return m, nil
		}
		m, ctx := m.beginSMBOperation()
		snapshot := m.smbBrowser
		store, project := m.store, m.current
		return m, func() tea.Msg {
			defer snapshot.cancel()
			window, limit := project.LockoutWindowMinutes, project.LockoutMaxAttempts
			if window <= 0 {
				window = domain.DefaultLockoutWindowMinutes
			}
			if limit <= 0 {
				limit = domain.DefaultLockoutMaxAttempts
			}
			n, err := store.RecentFailureCount(ctx, project.ID, cred.Username, time.Now().Add(-time.Duration(window)*time.Minute))
			if err != nil {
				return smbAuthDone{generation: snapshot.generation, err: err}
			}
			if n >= limit {
				return smbAuthDone{generation: snapshot.generation, err: fmt.Errorf("достигнут лимит ошибок входа для учётки")}
			}
			ok, err := js.NewSMBClient(ctx, 30*time.Second).LoginUsingCredential(snapshot.host, snapshot.port, cred)
			recordCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			recordErr := store.RecordAttempt(recordCtx, project.ID, fmt.Sprintf("%s:%d", snapshot.host, snapshot.port), cred.Username, "smb", ok)
			stop()
			if err == nil {
				err = recordErr
			}
			return smbAuthDone{snapshot.generation, cred, err}
		}
	}
	return m, nil
}

type smbAuthDone struct {
	generation int
	credential domain.Credential
	err        error
}

func (m model) applySMBAuthDone(done smbAuthDone) (tea.Model, tea.Cmd) {
	b := &m.smbBrowser
	if b.generation != done.generation {
		return m, nil
	}
	b.busy = false
	b.cancel = nil
	if done.err != nil {
		m.message = "SMB: " + smbDisplayName(done.err.Error())
		return m, nil
	}
	b.mode = "credential"
	b.credential = done.credential
	m.screen = "smb-browser"
	return m.loadSMBDirectory("", "")
}
func (m model) viewSMBCredentials(w int) string {
	b := m.smbBrowser
	body := headingStyle.Render("SMB — выбор учётки") + fmt.Sprintf("\n%s:%d\nПароль и NTLM-хеш не отображаются.\n", b.host, b.port)
	lo, hi := windowRange(b.credIndex, len(b.credentials), max(1, m.panelRows()-5))
	for i := lo; i < hi; i++ {
		body += renderListRow(credIdentLabel(b.credentials[i])+" · "+credTypeLabel(b.credentials[i].Type), i == b.credIndex, w)
	}
	body += "\nEnter вход · c Credentials · Esc назад"
	if b.busy {
		body += "\nПодключение… Esc отменить"
	}
	return m.renderPanel(w, body)
}
