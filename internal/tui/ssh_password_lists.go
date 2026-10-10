package tui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"os"
	"path/filepath"
)

type sshPasswordList struct {
	name, path string
	size       int64
}

func sshPasswordLists(appDir string) []sshPasswordList {
	choices := []sshPasswordList{}
	seen := map[string]bool{}
	for _, path := range []string{"/usr/share/wordlists/rockyou.txt", filepath.Join(appDir, "wordlists", "rockyou.txt")} {
		st, err := os.Stat(path)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		real, err := filepath.EvalSymlinks(path)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		choices = append(choices, sshPasswordList{"RockYou", path, st.Size()})
	}
	return choices
}
func defaultSSHPasswordList(appDir string) string {
	choices := sshPasswordLists(appDir)
	if len(choices) > 0 {
		return choices[0].path
	}
	return ""
}
func (m model) openSSHPasswordLists() (tea.Model, tea.Cmd) {
	b := &m.sshDictionary
	b.passwordLists = sshPasswordLists(m.appDir)
	b.passwordListIndex = 0
	m.screen = "ssh-password-lists"
	m.message = ""
	return m, nil
}
func (m model) updateSSHPasswordLists(key string) (tea.Model, tea.Cmd) {
	b := &m.sshDictionary
	switch key {
	case "esc", "q":
		m.screen = "ssh-dictionary"
	case "up", "k":
		b.passwordListIndex = max(0, b.passwordListIndex-1)
	case "down", "j":
		b.passwordListIndex = min(max(0, len(b.passwordLists)-1), b.passwordListIndex+1)
	case "f":
		m.startInput("ssh-dict-passwords")
		m.input = b.options.Passwordlist
	case "enter":
		if len(b.passwordLists) == 0 {
			m.message = "f — укажи свой файл паролей"
			return m, nil
		}
		choice := b.passwordLists[b.passwordListIndex]
		b.options.Passwordlist = choice.path
		m.screen = "ssh-dictionary"
		m.message = "Словарь паролей: " + choice.name
	}
	return m, nil
}
func (m model) viewSSHPasswordLists(w int) string {
	b := m.sshDictionary
	body := headingStyle.Render("SSH — словари паролей") + "\n↑/↓ выбрать · Enter применить · f свой файл · Esc назад\n\n"
	for i, c := range b.passwordLists {
		body += renderListRow(fmt.Sprintf("%s · %.1f МБ", c.name, float64(c.size)/1024/1024), i == b.passwordListIndex, w)
	}
	if len(b.passwordLists) == 0 {
		body += "Нет установленных словарей. f — свой файл."
	}
	return m.renderPanel(w, body)
}
