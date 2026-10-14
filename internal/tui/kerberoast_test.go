package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
)

func TestKerberoastRequiresSelectedCredential(t *testing.T) {
	m := model{ctx: context.Background(), current: domain.Project{ID: 1}, adAccessHost: "127.0.0.1", adAccessDomain: "lab.local", adAccessCred: -1}
	for i, row := range adAccessModes {
		if row.id == "kerberoast" {
			m.adAccessIndex = i
		}
	}
	result, command := m.startADAccess()
	got := result.(model)
	if command != nil || !strings.Contains(got.message, "учётку") {
		t.Fatal(got.message)
	}
	_, command = m.updateADAccess("s")
	if command != nil {
		t.Fatal("SPN input started a network job")
	}
}

func TestKerberoastFormFieldsRemainVisibleOnShortTerminals(t *testing.T) {
	m := model{screen: "ad-access", adAccessHost: "192.0.2.10", adAccessDomain: "lab.example", adKerberoastAuth: 1, adKerberoastNoPreauthUser: "legacy", adKerberoastSPNs: "HTTP/a"}
	for i, row := range adAccessModes {
		if row.id == "kerberoast" {
			m.adAccessIndex = i
		}
	}
	for _, height := range []int{20, 24, 32} {
		m.height = height
		view := ansi.Strip(m.viewADAccess(80))
		for _, field := range []string{"a Режим", "u Логин", "legacy", "s SPN", "HTTP/a", "e Шифрование"} {
			if !strings.Contains(view, field) {
				t.Fatalf("%s hidden at height %d", field, height)
			}
		}
	}
}

func TestKerberoastModeInputsKeepCredentialsSeparate(t *testing.T) {
	m := newTestModelForSettings(t)
	m.screen, m.adAccessHost, m.adAccessDomain = "ad-access", "192.0.2.10", "lab.example"
	m.adAccessCreds = []domain.Credential{{Type: "password", Username: "alice", Domain: "lab.example", Secret: "fixture-secret"}}
	m.adAccessCred = 0
	for i, row := range adAccessModes {
		if row.id == "kerberoast" {
			m.adAccessIndex = i
		}
	}
	key := func(s string) {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
		m = next.(model)
	}
	key("a")
	key("u")
	if m.screen != "input" || m.inputAction != "kerberoast-nopreauth-user" {
		t.Fatal("no-preauth login inaccessible")
	}
	m.input = "legacy"
	next, _ := m.Update(enterKey())
	m = next.(model)
	file := filepath.Join(t.TempDir(), "spns.txt")
	os.WriteFile(file, []byte("# fixture\nHTTP/service.lab.example|service\n"), 0600)
	key("s")
	m.input = "@" + file
	next, _ = m.Update(enterKey())
	m = next.(model)
	o, err := m.kerberoastOptions()
	if err != nil || o.NoPreauthUser != "legacy" || o.Credential.Username != "" || o.Credential.Secret != "" || len(o.SPNs) != 1 || o.TGTFile != "" {
		t.Fatal(o.NoPreauthUser, err)
	}
	key("e")
	o, err = m.kerberoastOptions()
	if err != nil || len(o.TGSEtypes) != 1 || o.TGSEtypes[0] != 23 {
		t.Fatal("RC4 selection ignored", err)
	}
	view := m.viewADAccess(100)
	if !strings.Contains(view, "Без пароля") || !strings.Contains(view, "SPN|логин") {
		t.Fatal("mode instructions missing")
	}
	key("a")
	key("t")
	if m.inputAction != "kerberoast-tgt-file" {
		t.Fatal("TGT input inaccessible")
	}
	m.input = filepath.Join(t.TempDir(), "ticket.kirbi")
	next, _ = m.Update(enterKey())
	m = next.(model)
	o, err = m.kerberoastOptions()
	if err != nil || o.TGTFile == "" || o.NoPreauthUser != "" || o.Credential.Username != "" || o.Credential.Secret != "" {
		t.Fatal(o.NoPreauthUser, err)
	}
	key("s")
	m.input = ""
	next, _ = m.Update(enterKey())
	m = next.(model)
	if m.screen != "ad-access" || m.adKerberoastSPNs != "" {
		t.Fatal("SPN list cannot be cleared")
	}
	if _, err := m.kerberoastOptions(); err == nil {
		t.Fatal("ticket mode accepted missing SPNs")
	}
	key("a")
	o, err = m.kerberoastOptions()
	if err != nil || o.Credential.Username != "alice" || o.TGTFile != "" || o.NoPreauthUser != "" {
		t.Fatal("password mode carries alternate material", err)
	}
}

func TestKerberoastMissingNoPreauthInputDoesNotStartTask(t *testing.T) {
	m := model{ctx: context.Background(), current: domain.Project{ID: 1}, adAccessHost: "192.0.2.10", adAccessDomain: "lab.example", adKerberoastAuth: 1}
	for i, row := range adAccessModes {
		if row.id == "kerberoast" {
			m.adAccessIndex = i
		}
	}
	for _, user := range []string{"", "legacy"} {
		m.adKerberoastNoPreauthUser = user
		next, cmd := m.startADAccess()
		if cmd != nil || len(next.(model).jobs) != 0 || next.(model).message == "" {
			t.Fatal("incomplete form started a task")
		}
	}
}
