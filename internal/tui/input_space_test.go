package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"testing"
)

func TestCommandInputAcceptsTypedAndPastedSpaces(t *testing.T) {
	for _, action := range []string{"mssql-command", "mssql-query", "winrm-command", "winrm-shell-command", "module-command", "cred-secret"} {
		m := model{screen: "input", inputAction: action}
		for _, key := range []tea.KeyMsg{{Type: tea.KeyRunes, Runes: []rune("whoami")}, {Type: tea.KeySpace}, {Type: tea.KeyRunes, Runes: []rune("/priv")}} {
			got, _ := m.Update(key)
			m = got.(model)
		}
		if m.input != "whoami /priv" {
			t.Fatalf("%s: input=%q", action, m.input)
		}
		got, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(" && echo hello world"), Paste: true})
		m = got.(model)
		if m.input != "whoami /priv && echo hello world" {
			t.Fatalf("%s: pasted input=%q", action, m.input)
		}
	}
}
