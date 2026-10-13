package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wscan/internal/adscan"
	"wscan/internal/domain"
)

func TestASREPSetupRestoresAllNamesAndKDCFromProject(t *testing.T) {
	m := newTestModelForSettings(t)
	m.appDir = t.TempDir()
	host := adscan.Host{Address: "192.0.2.10", Domain: "lab.example", Ports: []int{88, 389}}
	for i := 0; i < 150; i++ {
		host.LDAPUsers = append(host.LDAPUsers, fmt.Sprintf("user%03d", i))
	}
	raw, err := json.Marshal(host)
	if err != nil {
		t.Fatal(err)
	}
	run, err := m.store.StartRun(m.ctx, m.current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.store.SaveService(m.ctx, run, domain.Service{Host: host.Address, Port: 88, Protocol: "tcp", State: "open"}); err != nil {
		t.Fatal(err)
	}
	if err := m.store.SaveFinding(m.ctx, run, domain.Finding{TemplateID: "adscan-rootdse", Name: "RootDSE", Target: host.Address, MatchedAt: host.Address, Response: string(raw), Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	m.store.FinishRun(m.ctx, run, "completed")
	m.openProject(m.current)
	m.openADAccess()
	m.adAccessHost = "192.0.2.20" // Selected workstation must not become KDC.
	for i, mode := range adAccessModes {
		if mode.id == "asrep" {
			m.adAccessIndex = i
		}
	}
	next, _ := m.Update(enterKey())
	m = next.(model)
	if m.screen != "asrep-setup" || m.adAccessHost != "" || m.adAccessDomain != "lab.example" {
		t.Fatalf("setup %s %s %s", m.screen, m.adAccessHost, m.adAccessDomain)
	}
	o, err := m.asrepOptions()
	if err != nil || o.Host != host.Address || len(o.Users) != 150 || o.Users[149] != "user149" {
		t.Fatalf("lost persisted names/identity: %+v %v", o, err)
	}
	if view := m.viewASREPSetup(100); !strings.Contains(view, "Начать проверку") || strings.Contains(view, "пароль:") {
		t.Fatal(view)
	}
	// Switching projects must not reuse an earlier AD result or its user list.
	m.inventory = map[string]*hostInfo{}
	m.adScanResult = &adscan.Result{Hosts: []adscan.Host{host}}
	m.adAccessDomain = ""
	m.openASREPSetup()
	if m.adAccessDomain != "" {
		t.Fatal("domain leaked from another project")
	}
}

func TestASREPMenuEditsReturnAndClearAutomaticSettings(t *testing.T) {
	m := newTestModelForSettings(t)
	m.openASREPSetup()
	m.adASREPIndex = 1
	m.adAccessHost = "192.0.2.10"
	next, _ := m.Update(enterKey())
	m = next.(model)
	if m.screen != "ad-controller-picker" {
		t.Fatalf("controller picker not opened: %s", m.screen)
	}
	m.adControllerIndex = len(m.adControllerHosts()) + 1 // Manual IP/DNS remains available.
	next, _ = m.Update(enterKey())
	m = next.(model)
	if m.screen != "input" || m.input != "192.0.2.10" {
		t.Fatalf("wrong host input %s %q", m.screen, m.input)
	}
	m.input = ""
	next, _ = m.Update(enterKey())
	m = next.(model)
	if m.screen != "asrep-setup" || m.adAccessHost != "" {
		t.Fatal("KDC cannot be reset to automatic")
	}
	m.adASREPIndex = 2
	next, _ = m.Update(enterKey())
	m = next.(model)
	m.input = "alice,bob"
	next, _ = m.Update(enterKey())
	m = next.(model)
	if m.screen != "asrep-setup" || m.adASREPUsers != "alice,bob" {
		t.Fatal("users input did not return")
	}
	m.adASREPIndex = 4
	next, _ = m.Update(enterKey())
	m = next.(model)
	if m.screen != "ad-access" {
		t.Fatal("menu back failed")
	}
}

func TestASREPUserFileAndForeignRealm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")
	if err := os.WriteFile(path, []byte("# names\nAlice\nalice\nLAB\\bob\nmachine$\n"), 0600); err != nil {
		t.Fatal(err)
	}
	users, err := parseASREPUsersInput("@"+path, "lab.example")
	if err != nil || len(users) != 3 {
		t.Fatalf("%v %v", users, err)
	}
	if _, err := parseASREPUsersInput("alice@other.example", "lab.example"); err == nil {
		t.Fatal("foreign user accepted")
	}
	m := model{adAccessDomain: "lab.example", adASREPUsers: "@" + path, current: domain.Project{ID: 1}}
	if o, err := m.asrepOptions(); err != nil || len(o.Users) != 3 || o.Credential.Username != "" || o.Host != "" {
		t.Fatalf("manual list requires host/credentials: %+v %v", o, err)
	}
}
