package tui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"wscan/internal/adscan"
	"wscan/internal/domain"
)

func adIdentityHostInfo(t *testing.T, host adscan.Host) *hostInfo {
	t.Helper()
	raw, err := json.Marshal(host)
	if err != nil {
		t.Fatal(err)
	}
	info := &hostInfo{findings: []domain.Finding{{TemplateID: "adscan-rootdse", Response: string(raw), Time: time.Now()}}}
	for _, port := range host.Ports {
		info.services = append(info.services, domain.Service{Host: host.Address, Port: port, Protocol: "tcp", State: "open"})
	}
	return info
}

func TestADAccessPrefillsSelectedDomainAndController(t *testing.T) {
	m := newTestModelForSettings(t)
	m.inventory = map[string]*hostInfo{
		"192.0.2.10": adIdentityHostInfo(t, adscan.Host{Address: "192.0.2.10", Domain: "a.example", DCConfirmed: true, Ports: []int{389}}),
		"192.0.2.20": adIdentityHostInfo(t, adscan.Host{Address: "192.0.2.20", Domain: "b.example", DCConfirmed: true, Ports: []int{636}}),
		"192.0.2.30": adIdentityHostInfo(t, adscan.Host{Address: "192.0.2.30", Domain: "a.example", Ports: []int{445}}),
	}
	m.hostOrder = []string{"192.0.2.30"}
	m.hostIndex = 0
	m.screen = "ad-menu"
	m.adMenuIndex = 1
	next, cmd := m.Update(enterKey())
	m = next.(model)
	if cmd != nil || m.adAccessDomain != "a.example" || m.adAccessHost != "192.0.2.10" || m.adAccessLDAPPort != 389 {
		t.Fatalf("cached domain/controller not selected: %s %s %d", m.adAccessDomain, m.adAccessHost, m.adAccessLDAPPort)
	}
	if !strings.Contains(m.viewADAccess(100), "Домен: a.example") {
		t.Fatal("domain not visible before launch")
	}
}

func TestADAccessDoesNotChooseArbitraryDomain(t *testing.T) {
	m := newTestModelForSettings(t)
	m.inventory = map[string]*hostInfo{
		"192.0.2.10": adIdentityHostInfo(t, adscan.Host{Address: "192.0.2.10", Domain: "a.example", Ports: []int{389}}),
		"192.0.2.20": adIdentityHostInfo(t, adscan.Host{Address: "192.0.2.20", Domain: "b.example", Ports: []int{389}}),
	}
	m.hostIndex = -1
	m.openADAccess()
	if m.adAccessDomain != "" || m.adAccessHost != "" || m.detectADAccessIdentityCmd() != nil || !strings.Contains(m.adAccessHint, "a.example, b.example") {
		t.Fatal("ambiguous domains selected silently")
	}
}

func TestADIdentityBackgroundReplyPreservesManualEditsAndProject(t *testing.T) {
	m := newTestModelForSettings(t)
	m.screen = "ad-access"
	m.adAccessGeneration = 10
	m.adAccessAutoBusy = true
	reply := adAccessIdentityDetected{project: m.current.ID, generation: 10, nodes: []adscan.Host{{Address: "192.0.2.10", Domain: "lab.example", DCConfirmed: true, Ports: []int{389}}}}
	m.startInput("ad-access-domain")
	m.input = "manual.example"
	next, _ := m.Update(enterKey())
	m = next.(model)
	next, _ = m.Update(reply)
	m = next.(model)
	if m.adAccessDomain != "manual.example" || m.adAccessAutoBusy || m.adAccessHost != "" {
		t.Fatal("late probe overwrote manual domain")
	}
	m.adAccessDomain = ""
	m.adAccessGeneration = 10
	m.adAccessAutoBusy = true
	reply.project++
	m.applyADAccessIdentity(reply)
	if m.adAccessDomain != "" {
		t.Fatal("domain leaked across projects")
	}
	reply.project = m.current.ID
	m.applyADAccessIdentity(reply)
	if m.adAccessAutoBusy || m.adAccessDomain != "lab.example" || m.adAccessHost != "192.0.2.10" {
		t.Fatal("RootDSE response not applied")
	}
	m.openASREPSetup()
	if m.adAccessHost != "192.0.2.10" {
		t.Fatal("freshly detected KDC was lost in AS-REP setup")
	}
}
