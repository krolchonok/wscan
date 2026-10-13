package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"reflect"
	"strings"
	"testing"
	"wscan/internal/adscan"
	"wscan/internal/domain"
)

func TestCoercionTargetsScope(t *testing.T) {
	m := model{inventory: map[string]*hostInfo{
		"machine-a": {services: []domain.Service{{Host: "192.0.2.1", Port: 445, Protocol: "tcp", State: "open"}, {Host: "192.0.2.1", Port: 445, Protocol: "tcp", State: "open"}}},
		"machine-b": {services: []domain.Service{{Host: "192.0.2.2", Port: 445, Protocol: "tcp", State: "open"}}},
		"closed":    {services: []domain.Service{{Host: "192.0.2.3", Port: 445, Protocol: "tcp", State: "closed"}}},
		"udp":       {services: []domain.Service{{Host: "192.0.2.4", Port: 445, Protocol: "udp", State: "open"}}},
		"web":       {services: []domain.Service{{Host: "192.0.2.5", Port: 443, Protocol: "tcp", State: "open"}}},
	}}
	if got := m.coercionTargets(); !reflect.DeepEqual(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("all scope: %v", got)
	}
	m.selectedHosts = map[string]bool{"machine-b": true}
	if got := m.coercionTargets(); !reflect.DeepEqual(got, []string{"192.0.2.2"}) {
		t.Fatalf("selected scope: %v", got)
	}
	m.selectedHosts = map[string]bool{"web": true}
	if got := m.coercionTargets(); len(got) != 0 {
		t.Fatalf("must not fall back to all targets: %v", got)
	}
	m.adAccessHost = "192.0.2.9"
	if got := m.coercionTargets(); !reflect.DeepEqual(got, []string{"192.0.2.9"}) {
		t.Fatalf("explicit host: %v", got)
	}
}

func TestCoercionMenuOpensHostSetup(t *testing.T) {
	m := newTestModelForSettings(t)
	m.screen = "desk"
	m.hostOrder = []string{"127.0.0.1"}
	m.inventory = map[string]*hostInfo{"127.0.0.1": {services: []domain.Service{{Host: "127.0.0.1", Port: 445, Protocol: "tcp", State: "open"}}}}
	m.screen = "ad-menu"
	m.adMenuIndex = 2
	next, cmd := m.updateADMenu("enter")
	m = next.(model)
	if m.screen != "coerce-setup" || m.adAccessHost != "127.0.0.1" || cmd == nil || len(m.jobs) != 0 {
		t.Fatal("menu must open host setup without starting Coerce or receiver")
	}
	next, _ = m.Update(cmd())
	m = next.(model)
	if m.adCoerceCallback != "127.0.0.1" || !m.coerceCallbackAuto {
		t.Fatalf("local route not selected: %s", m.adCoerceCallback)
	}
	if !strings.Contains(m.viewCoercionSetup(100), "Запустить Responder") {
		t.Fatal("receiver startup not offered")
	}
	next, _ = m.updateCoercionSetup("esc")
	if next.(model).screen != "ad-menu" {
		t.Fatal("lost return menu")
	}
}
func TestCoercionManualAddressSurvivesStaleRoute(t *testing.T) {
	m := model{screen: "coerce-setup", adAccessHost: "192.0.2.10", adCoerceCallback: "192.0.2.16", coerceCallbackAuto: false}
	next, _ := m.applyCoerceRoute(coerceRouteReady{host: "192.0.2.10", ip: "192.0.2.17"})
	if next.(model).adCoerceCallback != "192.0.2.16" {
		t.Fatal("manual address overwritten")
	}
	m.coerceCallbackAuto = true
	next, _ = m.applyCoerceRoute(coerceRouteReady{host: "192.0.2.11", ip: "192.0.2.17"})
	if next.(model).adCoerceCallback != "192.0.2.16" {
		t.Fatal("stale target route applied")
	}
}
func TestCoercionInputReturnsToHostSetup(t *testing.T) {
	m := model{screen: "coerce-setup"}
	m.startInput("ad-coerce-callback")
	m.input = "192.0.2.16"
	next, _ := m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if m.screen != "coerce-setup" || m.adCoerceCallback != "192.0.2.16" || m.coerceCallbackAuto {
		t.Fatal("address editor lost setup screen or override")
	}
	m.startInput("ad-access-domain")
	m.input = "LAB"
	next, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if m.screen != "coerce-setup" || m.adAccessDomain != "LAB" {
		t.Fatal("domain editor lost setup screen")
	}
}

func TestCoercionPortRequiresConfirmation(t *testing.T) {
	m := model{screen: "coerce-setup", adCoerceCallback: "192.0.2.16"}
	next, cmd := m.requestCoercionPort("responder")
	m = next.(model)
	if cmd == nil || m.screen != "coerce-port-check" || len(m.jobs) != 0 {
		t.Fatal("preflight must not start receiver")
	}
	next, _ = m.applyCoercionPortChecked(coercePortChecked{generation: m.coercePortGeneration, owners: []adscan.PortOwner{{PID: 123, Name: "smbd", StartTime: "100", Service: "smbd"}}})
	m = next.(model)
	if m.screen != "coerce-port-confirm" || len(m.jobs) != 0 {
		t.Fatal("occupied port must require confirmation")
	}
	if !strings.Contains(m.viewCoercionPort(100), "PID 123") {
		t.Fatal("owner not displayed")
	}
	generation := m.coercePortGeneration
	next, cmd = m.updateCoercionPort("n")
	m = next.(model)
	if cmd != nil || m.screen != "coerce-setup" || m.coercePortGeneration == generation || len(m.jobs) != 0 {
		t.Fatal("cancellation must not stop processes or start jobs")
	}
	next, _ = m.applyCoercionPortChecked(coercePortChecked{generation: generation})
	if next.(model).coercePortApproved {
		t.Fatal("cancelled port approval applied later")
	}
}

func TestADAccessMenuKeepsSelectedCoercionHost(t *testing.T) {
	m := newTestModelForSettings(t)
	m.screen = "ad-menu"
	m.adMenuIndex = 2
	m.hostOrder = []string{"127.0.0.1"}
	m.hostIndex = 0
	m.inventory = map[string]*hostInfo{
		"127.0.0.1": {services: []domain.Service{{Host: "127.0.0.1", Port: 445, Protocol: "tcp", State: "open"}}},
		"192.0.2.2": {services: []domain.Service{{Host: "192.0.2.2", Port: 445, Protocol: "tcp", State: "open"}}},
	}
	next, cmd := m.updateADMenu("enter")
	m = next.(model)
	if got := m.coercionTargets(); !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
		t.Fatalf("host menu widened targets: %v", got)
	}
	if cmd == nil {
		t.Fatal("receiver route lookup missing")
	}
	next, _ = m.Update(cmd())
	m = next.(model)
	if m.adCoerceCallback != "127.0.0.1" {
		t.Fatalf("receiver: %s", m.adCoerceCallback)
	}
	if !strings.Contains(m.viewCoercionSetup(100), "Цель: 127.0.0.1") {
		t.Fatal("target scope unclear")
	}
}
