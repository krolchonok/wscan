package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
)

func TestFindingMSFCommandMappingsAndEndpoints(t *testing.T) {
	for _, tc := range []struct {
		id, matched, target, module, host, port string
	}{
		{"adscan-smb-vuln-ms17-010", "tcp://10.0.5.10:1445", "10.0.5.0/24", "exploit/windows/smb/ms17_010_eternalblue", "10.0.5.10", "1445"},
		{"nmap/smb-vuln-ms17-010", "10.0.5.11:445", "", "exploit/windows/smb/ms17_010_eternalblue", "10.0.5.11", "445"},
		{"nmap/smb-vuln-ms17-010", "nse://10.0.5.11:1445/smb-vuln-ms17-010", "10.0.5.0/24", "exploit/windows/smb/ms17_010_eternalblue", "10.0.5.11", "1445"},
		{"CVE-2017-0143", "", "windows.lab", "exploit/windows/smb/ms17_010_eternalblue", "windows.lab", "445"},
		{"custom/windows-rce/CVE-2017-0143.yaml", "tcp://windows.lab:445", "", "exploit/windows/smb/ms17_010_eternalblue", "windows.lab", "445"},
		{"adscan-ms12-020", "tcp://10.0.5.12:13389", "10.0.5.0/24", "auxiliary/scanner/rdp/ms12_020_check", "10.0.5.12", "13389"},
		{"nmap/rdp-vuln-ms12-020", "", "rdp.lab:3389", "auxiliary/scanner/rdp/ms12_020_check", "rdp.lab", "3389"},
		{"nmap/rdp-vuln-ms12-020", "nse://rdp.lab:3389/rdp-vuln-ms12-020", "", "auxiliary/scanner/rdp/ms12_020_check", "rdp.lab", "3389"},
		{"msf-rdp-ms12-020-check", "tcp://[2001:db8::10]:3390", "", "auxiliary/scanner/rdp/ms12_020_check", "2001:db8::10", "3390"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			f := domain.Finding{TemplateID: tc.id, Severity: "critical", Target: tc.target, MatchedAt: tc.matched}
			command, explanation, ok := findingMSFCommand(f)
			if !ok || explanation == "" {
				t.Fatal("missing command or explanation")
			}
			for _, part := range []string{"msfconsole -q -x 'use " + tc.module, "; set RHOSTS " + tc.host + ";", "; set RPORT " + tc.port, "; run'"} {
				if !strings.Contains(command, part) {
					t.Fatalf("command %q missing %q", command, part)
				}
			}
			if strings.ContainsAny(command, "\r\n") {
				t.Fatal("copyable command must be a single line")
			}
			if strings.Contains(command, "LHOST") || strings.Contains(explanation, "LHOST") {
				t.Fatal("generated commands must not set LHOST or include its placeholder")
			}
			if strings.HasPrefix(tc.module, "auxiliary/") {
				if strings.Contains(command, "PAYLOAD") || strings.Contains(command, "LHOST") || !strings.Contains(explanation, "проверочный") {
					t.Fatal("RDP checker misrepresented as an exploit")
				}
			} else if !strings.Contains(command, "set PAYLOAD windows/x64/meterpreter/reverse_tcp") || !strings.Contains(explanation, "x64") {
				t.Fatal("EternalBlue template must retain its payload and architecture")
			}
		})
	}
}

func TestFindingMSFCommandRejectsUnsafeTargets(t *testing.T) {
	for _, address := range []string{
		"", "10.0.5.0/24", "10.0.5.10 10.0.5.11", "10.0.5.10; run", "host'", "host`id`", "$(id)", "host\nexit", "host\x1b[31m",
		"host:0", "host:65536", "host:-1", "host:bad", "tcp://host:", "tcp://host:bad", "tcp://host:65536", "udp://host:445",
		"http://host:445", "tcp://user@host:445", "tcp://host:445/path", "tcp://host:445?run", "tcp://host:445#run", "tcp://host%20name:445",
		"-host", "host-", "a..b", "tcp://[fe80::1%25eth0]:445",
	} {
		t.Run(address, func(t *testing.T) {
			f := domain.Finding{TemplateID: "CVE-2017-0143", Severity: "critical", Target: address}
			if command, _, ok := findingMSFCommand(f); ok || command != "" {
				t.Fatalf("unsafe target generated command: %q", command)
			}
			// A bad MatchedAt must not silently fall back to a different target.
			if address != "" {
				f.MatchedAt, f.Target = address, "10.0.5.20:445"
				if _, _, ok := findingMSFCommand(f); ok {
					t.Fatal("invalid matched endpoint fell back to target")
				}
			}
		})
	}
}

func TestFindingMSFCommandUsesOnlyCuratedRiskFindings(t *testing.T) {
	for _, f := range []domain.Finding{
		{TemplateID: "unknown", Severity: "critical", Name: "MS17-010 EternalBlue", Evidence: "CVE-2017-0143"},
		{TemplateID: "CVE-2017-0143", Severity: "error"},
		{TemplateID: "CVE-2017-0143", Severity: "info"},
		{TemplateID: "CVE-2017-0143", Severity: "critical", Protocol: "udp"},
		{TemplateID: "nmap/smb-vuln-ms17-010", Severity: "critical", Evidence: "ERROR: connection refused"},
	} {
		f.Target = "10.0.5.10:445"
		if command, _, ok := findingMSFCommand(f); ok {
			t.Fatalf("unexpected command for %+v: %q", f, command)
		}
	}
}

func TestFindingCommandNavigationDoesNotLaunchAnything(t *testing.T) {
	f := domain.Finding{TemplateID: "adscan-ms12-020", Severity: "critical", Target: "10.0.5.10:3389"}
	m := model{screen: "project-results", findingDetail: &f, width: 80, height: 35}
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	m = updated.(model)
	if cmd != nil || m.findingPane != 1 || m.findingSection != 3 || m.findingRaw {
		t.Fatal("m should only open generated command")
	}
	if got := strings.Join(m.projectResultDetailLines(300), "\n"); !strings.Contains(got, "msfconsole -q -x") || strings.Contains(got, "YOUR_LHOST") {
		t.Fatalf("incorrect RDP command view: %s", got)
	}
	updated, cmd = m.updateProjectResults("tab")
	m = updated.(model)
	if cmd != nil || m.findingSection != 0 {
		t.Fatal("fourth tab must wrap back to overview")
	}
	updated, _ = m.updateProjectResults("shift+tab")
	m = updated.(model)
	if m.findingSection != 3 {
		t.Fatal("reverse tab must reach command")
	}
	updated, cmd = m.updateProjectResults("y")
	if cmd == nil {
		t.Fatal("native copy should produce a clipboard command")
	}
	// Web transport must never write escape sequences to the server's terminal.
	m = updated.(model)
	m.clientSource = "web-terminal"
	updated, cmd = m.updateProjectResults("y")
	if cmd != nil || !strings.Contains(updated.(model).message, "браузера") {
		t.Fatal("web view should retain browser text selection")
	}
	unsupported := domain.Finding{TemplateID: "unknown", Severity: "critical", Target: f.Target}
	m.findingDetail, m.findingSection = &unsupported, 0
	if len(m.findingSections()) != 3 {
		t.Fatal("unsupported finding should keep original three tabs")
	}
	updated, cmd = m.updateProjectResults("m")
	if cmd != nil || updated.(model).findingSection != 0 {
		t.Fatal("unsupported finding must not generate a command")
	}
}

func TestDeskCommandShortcutUsesHighlightedFindingAndReturnsToDesk(t *testing.T) {
	for _, width := range []int{60, 100, 160} {
		host := "10.0.5.10"
		f := domain.Finding{TemplateID: "adscan-smb-vuln-ms17-010", Name: "MS17-010 / EternalBlue", Severity: "critical", Target: host + ":1445", MatchedAt: "tcp://" + host + ":1445"}
		other := domain.Finding{TemplateID: "another-risk", Name: "Other vulnerability", Severity: "critical", Target: f.Target, MatchedAt: f.MatchedAt}
		m := model{screen: "desk", width: width, height: 40, focusCol: 2, hostOrder: []string{host}, hostIndex: 0, serviceIndex: 0, inventory: map[string]*hostInfo{
			host: {services: []domain.Service{{Host: host, Port: 1445, Protocol: "tcp"}}, findings: []domain.Finding{other, f}},
		}}
		for i, finding := range m.deskFindings() {
			if finding.TemplateID == f.TemplateID {
				m.findingIndex = i
			}
		}
		if !strings.Contains(m.footer(), "m команда msfconsole") || !strings.Contains(ansi.Strip(m.renderDetailsColumn(50, 30)), "m — команда msfconsole") {
			t.Fatalf("hotkey not visible while highlighting MS17-010 at width %d", width)
		}
		next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
		m = next.(model)
		if cmd != nil || m.screen != "project-results" || m.findingSection != 3 || m.findingDetail == nil || m.findingDetail.TemplateID != f.TemplateID {
			t.Fatal("desk hotkey did not open selected finding's command directly")
		}
		command, _, ok := findingMSFCommand(*m.findingDetail)
		if !ok || !strings.Contains(command, "set RHOSTS "+host) || !strings.Contains(command, "set RPORT 1445") {
			t.Fatalf("incorrect command for selected desk row: %q", command)
		}
		next, cmd = m.updateProjectResults("esc")
		m = next.(model)
		if cmd != nil || m.screen != "desk" || m.focusCol != 2 || m.currentHost() != host || m.serviceIndex != 0 {
			t.Fatal("Esc did not return to the same host and port")
		}
		for i, finding := range m.deskFindings() {
			if finding.TemplateID == other.TemplateID {
				m.findingIndex = i
			}
		}
		if m.deskCommandAvailable() || strings.Contains(m.footer(), "msfconsole") {
			t.Fatal("hotkey advertised for unsupported highlighted finding")
		}
		next, cmd = m.updateDesk("m")
		if cmd != nil || next.(model).screen != "desk" {
			t.Fatal("unsupported desk row opened a different finding's command")
		}
		m.focusCol = 0
		if m.deskCommandAvailable() {
			t.Fatal("host cursor must not silently select a vulnerability")
		}
	}
}
