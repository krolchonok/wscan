package tui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHPasswordListSelection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wordlists", "rockyou.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := model{appDir: dir, screen: "ssh-dictionary"}
	got, _ := m.openSSHPasswordLists()
	m = got.(model)
	found := false
	for i, c := range m.sshDictionary.passwordLists {
		if c.path == path {
			m.sshDictionary.passwordListIndex = i
			found = true
			break
		}
	}
	if !found {
		t.Fatal("managed RockYou missing")
	}
	got, _ = m.updateSSHPasswordLists("enter")
	m = got.(model)
	if m.screen != "ssh-dictionary" || m.sshDictionary.options.Passwordlist != path {
		t.Fatal("dictionary not selected")
	}
	got, _ = m.updateSSHDictionary("p")
	m = got.(model)
	if m.screen != "ssh-password-lists" {
		t.Fatal("p must open picker")
	}
	got, _ = m.updateSSHPasswordLists("f")
	m = got.(model)
	m.input = "/tmp/own-passwords.txt"
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.screen != "ssh-dictionary" || m.sshDictionary.options.Passwordlist != "/tmp/own-passwords.txt" {
		t.Fatal("manual file failed")
	}
}
