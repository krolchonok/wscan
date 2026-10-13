package tui

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"wscan/internal/adscan"
)

func TestManualControllerPickerPersistsWithoutChangingDetectedRoles(t *testing.T) {
	m := newTestModelForSettings(t)
	m.inventory = map[string]*hostInfo{
		"192.0.2.10": adIdentityHostInfo(t, adscan.Host{Address: "192.0.2.10", Domain: "lab.example", DCConfirmed: true, Ports: []int{389}}),
		"192.0.2.20": adIdentityHostInfo(t, adscan.Host{Address: "192.0.2.20", Domain: "lab.example", HostName: "member.lab.example", Ports: []int{445}}),
	}
	m.hostOrder = []string{"192.0.2.10", "192.0.2.20"}
	m.hostIndex = 0
	m.openADAccess()
	old := adAccessIdentityDetected{project: m.current.ID, generation: m.adAccessGeneration, host: m.adAccessHost, domain: m.adAccessDomain, nodes: []adscan.Host{{Address: "192.0.2.10", Domain: "lab.example", DCConfirmed: true, Ports: []int{389}}}}
	next, _ := m.updateADAccess("h")
	m = next.(model)
	if m.screen != "ad-controller-picker" {
		t.Fatal("host key did not open machines")
	}
	for i, host := range m.adControllerHosts() {
		if host == "192.0.2.20" {
			m.adControllerIndex = i + 1
		}
	}
	next, cmd := m.Update(enterKey())
	m = next.(model)
	if cmd != nil || m.screen != "ad-access" || m.adAccessManualHost != "192.0.2.20" || m.adAccessHost != "192.0.2.20" {
		t.Fatalf("manual choice not applied: %s %s", m.screen, m.adAccessHost)
	}
	host, realm, err := m.store.ADController(m.ctx, m.current.ID)
	if err != nil || host != "192.0.2.20" || realm != "lab.example" {
		t.Fatalf("selection not saved: %s %s %v", host, realm, err)
	}
	m.applyADAccessIdentity(old)
	if m.adAccessHost != host {
		t.Fatal("late auto result replaced selection")
	}
	for _, node := range m.projectADInventory().Hosts {
		if node.Address == host && node.DCConfirmed {
			t.Fatal("manual selection was presented as LDAP confirmation")
		}
	}
	m.openADAccess()
	if m.adAccessHost != host {
		t.Fatal("opening checks replaced saved selection")
	}
	m.openASREPSetup()
	if o, err := m.asrepOptions(); err != nil || o.Host != host {
		t.Fatalf("AS-REP lost selected controller: %+v %v", o, err)
	}
	m.startInput("ad-access-domain")
	m.input = "manual.example"
	next, _ = m.Update(enterKey())
	m = next.(model)
	if m.adAccessHost != host {
		t.Fatal("editing domain replaced controller")
	}
	if saved, realm, err := m.store.ADController(m.ctx, m.current.ID); err != nil || saved != host || realm != "manual.example" {
		t.Fatal("manual domain not saved")
	}
	if err := m.setADController(host); err != nil || m.adAccessDomain != "manual.example" {
		t.Fatal("reselecting controller replaced manual domain")
	}
	m.openADControllerPicker()
	m.adControllerIndex = 0
	next, _ = m.Update(enterKey())
	m = next.(model)
	if m.adAccessManualHost != "" || m.adAccessHost != "192.0.2.10" {
		t.Fatal("automatic selection not restored")
	}
}

func TestControllerPickerListsIndividualMachinesInNumericOrder(t *testing.T) {
	m := newTestModelForSettings(t)
	m.current.Targets = []string{"192.0.2.0/24", "192.0.2.10", "192.0.2.2", "dc.lab.example"}
	m.hostOrder = []string{"192.0.2.20", "192.0.2.10"}
	if got := m.adControllerHosts(); !reflect.DeepEqual(got, []string{"192.0.2.2", "192.0.2.10", "192.0.2.20", "dc.lab.example"}) {
		t.Fatalf("bad PC list: %v", got)
	}
	m.screen = "ad-menu"
	m.adMenuIndex = 3
	next, _ := m.Update(enterKey())
	m = next.(model)
	if m.screen != "ad-controller-picker" || m.adControllerReturn != "ad-menu" {
		t.Fatal("AD menu does not expose controller choice")
	}
	for i := 1; i <= 60; i++ {
		m.current.Targets = append(m.current.Targets, fmt.Sprintf("192.0.2.%d", i))
	}
	m.width, m.height = 55, 18
	for i, host := range m.adControllerHosts() {
		if host == "192.0.2.55" {
			m.adControllerIndex = i + 1
		}
	}
	if view := ansi.Strip(m.View()); !strings.Contains(view, "192.0.2.55") || !strings.Contains(view, "▶") {
		t.Fatal("selected PC is hidden below viewport")
	}
}
