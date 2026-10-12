package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/adscan"
	"wscan/internal/domain"
)

func TestADReconAdvancedOptionsAreEditableAndClearable(t *testing.T) {
	m := model{screen: "ad-scan", width: 110, height: 30}
	got, _ := m.updateADScan("d")
	if got.(model).screen != "ad-scan" {
		t.Fatal("advanced control leaked into default path")
	}
	got, _ = m.updateADScan("a")
	m = got.(model)
	got, _ = m.updateADScan("d")
	m = got.(model)
	if m.inputAction != "ad-recon-dns" {
		t.Fatal("DNS editor not opened")
	}
	m.input = "10.20.0.10, 10.20.0.11:5353"
	got, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = got.(model)
	if m.screen != "ad-scan" || len(m.adScanDNS.Servers) != 2 {
		t.Fatalf("DNS input not saved: %+v", m.adScanDNS)
	}
	m.startInput("ad-recon-domains")
	m.input = "LAB.Example."
	got, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = got.(model)
	if len(m.adScanDNS.Domains) != 1 || m.adScanDNS.Domains[0] != "lab.example" {
		t.Fatal("domain input not normalized")
	}
	m.startInput("ad-recon-dns")
	m.input = "not-an-ip"
	got, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = got.(model)
	if len(m.adScanDNS.Servers) != 2 || !strings.Contains(m.message, "DNS") {
		t.Fatal("invalid input replaced prior DNS options")
	}
	m.startInput("ad-recon-dns")
	got, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = got.(model)
	if len(m.adScanDNS.Servers) != 0 {
		t.Fatal("empty DNS input cannot clear options")
	}
	if text := m.viewADScan(100); !strings.Contains(text, "1. Выберите подсеть") || !strings.Contains(text, "n Домены") {
		t.Fatal("AD action path not visible")
	}
	// Configuration belongs to one invocation, not whichever project opens next.
	m.openADScan()
	if len(m.adScanDNS.Domains) != 0 || m.adScanAdvanced {
		t.Fatal("options leaked to next scan form")
	}
}

func TestADReconSummarySeparatesConfirmedAndAdvertisedDCs(t *testing.T) {
	result := adscan.Result{CIDR: "10.20.0.0/24", HostsScanned: 254, Hosts: []adscan.Host{
		{Address: "10.20.0.10", Roles: []string{"Контроллер домена"}},
		{Address: "10.20.0.11", Roles: []string{"Предполагаемый контроллер домена"}},
	}, Diagnostics: []string{"DNS SRV: покрытие неполное"}, DNSRecords: []adscan.SRVRecord{{Domain: "lab.example"}}}
	text := adReconSummary(result.CIDR, result, nil).Evidence
	for _, want := range []string{"DC: 1", "Предполагаемые DC: 1", "покрытие неполное", "lab.example"} {
		if !strings.Contains(text, want) {
			t.Fatalf("summary missing %q: %s", want, text)
		}
	}
	f := domain.Finding{TemplateID: "adscan-role-domain-controller-candidate"}
	if !adFindingOnPort(f, domain.Service{Port: 88, Protocol: "tcp"}) || adFindingOnPort(f, domain.Service{Port: 80, Protocol: "tcp"}) {
		t.Fatal("candidate DC mapped to wrong services")
	}
}
