package tui

import (
	"context"
	"strings"
	"testing"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

func TestSSHDictionaryInteractionAndPermission(t *testing.T) {
	service := domain.Service{Host: "127.0.0.1", Port: 2222, Name: "ssh", Protocol: "tcp"}
	m := newTestModelForSettings(t)
	m.screen = "desk"
	m.hostOrder = []string{service.Host}
	m.inventory = map[string]*hostInfo{service.Host: {services: []domain.Service{service}}}
	m.focusCol = 1
	m.openInteractionMenu()
	if m.interactionIndex != 8 {
		t.Fatal("SSH interaction missing")
	}
	got, cmd := m.updateInteractionMenu("enter")
	m = got.(model)
	if cmd != nil || m.screen != "ssh-dictionary" || m.sshDictionary.target.Port != 2222 {
		t.Fatal("wrong SSH target")
	}
	m.sshDictionary.options.Passwordlist = "/tmp/passwords.txt"
	got, cmd = m.startSSHDictionary()
	if cmd != nil || !strings.Contains(got.(model).message, "credential") {
		t.Fatal("permission gate bypassed")
	}
}
func TestSSHDictionaryCancelAndStaleCompletion(t *testing.T) {
	cancelled := false
	m := model{sshDictionary: sshDictionaryState{generation: 2, busy: true, cancel: func() { cancelled = true }}}
	got, _ := m.updateSSHDictionary("esc")
	m = got.(model)
	if !cancelled || !m.sshDictionary.busy {
		t.Fatal("cancel should await completion")
	}
	got, _ = m.applySSHDictionaryDone(sshDictionaryDone{generation: 1})
	if !got.(model).sshDictionary.busy {
		t.Fatal("stale completion applied")
	}
}
func TestSSHDictionarySaveSuccessfulCredential(t *testing.T) {
	m := newTestModelForSettings(t)
	m.sshDictionary.target.Host = "127.0.0.1"
	m.sshDictionary.rows = []engine.SSHDictionaryAttempt{{Attempt: domain.AuthAttempt{Username: "admin", Success: true}, Password: "good"}}
	got, _ := m.updateSSHDictionary("a")
	m = got.(model)
	creds, err := m.store.ListCredentials(context.Background(), m.current.ID)
	if err != nil || len(creds) != 1 || creds[0].Username != "admin" || creds[0].Secret != "good" {
		t.Fatalf("%v %v", creds, err)
	}
}

func TestSSHDictionaryUnlimitedDefaultAndToggle(t *testing.T) {
	m := model{smbBrowser: smbBrowserState{host: "127.0.0.1"}}
	got, _ := m.openSSHDictionary()
	m = got.(model)
	if !m.sshDictionary.options.Unlimited {
		t.Fatal("default limit still active")
	}
	got, _ = m.updateSSHDictionary("b")
	m = got.(model)
	if m.sshDictionary.options.Unlimited {
		t.Fatal("project limit toggle failed")
	}
}
