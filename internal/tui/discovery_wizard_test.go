package tui

import (
	"reflect"
	"testing"
	"wscan/internal/catalog"
)

func TestGuidedPortScanOpensParametersBeforeLaunching(t *testing.T) {
	m := newTestModelForSettings(t)
	m.cat = catalog.NewWithLibrary(t.TempDir(), t.TempDir())
	m.screen = "guided-scan"
	m.wizardStep = 2
	m.wizardProfile = 0
	m.wizardScope = "192.0.2.0/24"
	next, cmd := m.updateGuidedScan("enter")
	m = next.(model)
	if cmd != nil || m.screen != "disc-options" || len(m.jobs) != 0 || !reflect.DeepEqual(m.discHosts, []string{"192.0.2.0/24"}) {
		t.Fatal("port scan bypassed parameters or changed scope")
	}
	m.discSetIndex = 4
	m.discCustom = "22,80,443"
	m.discUDP = true
	m.discVersion = false
	m.discProject.DiscoveryRPS = 17
	spec, message := m.buildDiscoverSpec()
	if message != "" || !reflect.DeepEqual(spec.discPorts, []int{22, 80, 443}) || !reflect.DeepEqual(spec.discUDPPorts, []int{22, 80, 443}) || !spec.discNoVersion || spec.parameters.DiscoveryRPS != 17 {
		t.Fatalf("parameters lost: %+v %s", spec, message)
	}
	next, _ = m.updateDiscOptions("esc")
	if next.(model).screen != "guided-scan" {
		t.Fatal("lost wizard return")
	}
}

func TestEnterOnPortParametersUsesLaunchValidation(t *testing.T) {
	for _, index := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9} {
		m := newTestModelForSettings(t)
		m.cat = catalog.NewWithLibrary(t.TempDir(), t.TempDir())
		m.actionHosts = []string{"192.0.2.10"}
		m.screen = "action-menu"
		m.openDiscOptions()
		m.discOptIndex = index
		m.discTCP, m.discUDP = false, false
		next, cmd := m.updateDiscOptions("enter")
		m = next.(model)
		if cmd != nil || len(m.jobs) != 0 || m.message != "Выбери TCP и/или UDP" || m.screen != "disc-options" {
			t.Fatalf("Enter on %d did not use scan launch validation: %s", index, m.message)
		}
	}
}

func TestPortProfileGoesStraightToSettings(t *testing.T) {
	m := newTestModelForSettings(t)
	m.current.Targets = []string{"10.0.0.0/24", "10.0.0.1", "10.0.0.116"}
	m.openGuidedScan()
	if m.wizardStep != 1 {
		t.Fatal("existing project still asks for scope confirmation")
	}
	next, cmd := m.updateGuidedScan("enter")
	m = next.(model)
	if cmd != nil || m.screen != "disc-options" || len(m.jobs) != 0 || m.wizardStep != 1 {
		t.Fatal("port profile did not directly open settings")
	}
	if !reflect.DeepEqual(m.discHosts, m.current.Targets) {
		t.Fatal("display simplification changed scope")
	}
	next, _ = m.updateDiscOptions("esc")
	m = next.(model)
	if m.screen != "guided-scan" || m.wizardStep != 1 {
		t.Fatal("back returned to an extra confirmation")
	}
}

func TestScanScopeLabelIsCompactAndPreservesOutsideTargets(t *testing.T) {
	for _, test := range []struct{ scope, want string }{
		{"10.0.0.0/24 10.0.0.1 10.0.0.116", "10.0.0.0/24"},
		{"10.0.0.0/24 10.0.0.1 10.0.1.10", "10.0.0.0/24 · ещё 1 целей"},
		{"10.0.0.0/24 http://10.0.0.10/path", "10.0.0.0/24 · ещё 1 целей"},
	} {
		if got := scanScopeLabel(test.scope); got != test.want {
			t.Fatalf("scope label %q, want %q", got, test.want)
		}
	}
}
