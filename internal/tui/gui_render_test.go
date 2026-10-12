package tui

import (
	"fmt"
	"github.com/charmbracelet/x/ansi"
	"strings"
	"testing"
	"time"
	"wscan/internal/domain"
)

func TestGUIScreensFitAfterResize(t *testing.T) {
	screens := []string{"projects", "desk", "networks", "jobs", "job-details", "history", "project-results", "finding-details", "interaction-menu", "interaction-targets", "smb-setup", "smb-browser", "ftp-setup", "ftp-browser", "winrm-setup", "winrm-browser", "winrm-shell", "pg-setup", "pg-console", "mysql-setup", "mysql-console", "mssql-setup", "mssql-console", "mssql-actions", "mssql-xp-confirm", "web-discovery", "web-wordlists", "sqli-form", "file-upload", "lfi-audit", "ssh-dictionary", "ssh-password-lists", "kyocera-book", "coerce-setup", "ad-access", "ad-scan", "coerce-port-check", "coerce-port-confirm", "coerce-port-stopping", "service-inventory", "host-selection", "host-port-selection", "action-menu", "disc-options", "scan-review", "catalog", "catalog-groups", "global-settings", "settings", "speed-presets", "library-settings", "dependency-settings", "dependency-install-confirm", "credentials", "cred-add-type", "cred-delete-confirm", "project-delete-confirm", "delete-confirm", "repair-target", "input", "help", "code-exec-confirm", "exploit-confirm", "credential-attack-confirm", "spray-setup", "spray-running", "spray-results", "spray-module-picker", "spray-module-result"}
	for _, screen := range screens {
		t.Run(screen, func(t *testing.T) {
			m := newTestModelForSettings(t)
			m.screen = screen
			m.inventory = resultScopeFixture().inventory
			m.hostOrder = []string{"10.0.0.10"}
			m.findingDetail = nil
			m.jobs = []*job{{id: 1, projectID: m.current.ID, label: "Тест", status: statusRunning, started: time.Now(), stage: "Ожидание"}}
			for _, size := range [][2]int{{55, 18}, {100, 24}, {160, 40}} {
				m.width, m.height = size[0], size[1]
				lines := strings.Split(m.View(), "\n")
				if len(lines) != m.height {
					t.Fatalf("%dx%d: rows=%d", m.width, m.height, len(lines))
				}
				for _, line := range lines {
					if n := ansi.StringWidth(line); n != m.width {
						t.Fatalf("width=%d, want %d", n, m.width)
					}
				}
			}
		})
	}
}

func TestResultSelectionVisibleInSmallTerminal(t *testing.T) {
	m := resultScopeFixture()
	m.width, m.height = 55, 18
	m.inventory = map[string]*hostInfo{"10.0.0.10": {}}
	for i := 0; i < 30; i++ {
		m.inventory["10.0.0.10"].findings = append(m.inventory["10.0.0.10"].findings, domain.Finding{Target: "10.0.0.10", MatchedAt: "tcp://10.0.0.10:80", TemplateID: fmt.Sprint(i), Name: fmt.Sprintf("RESULT-%02d", i), Severity: "high"})
	}
	m.openProjectResults()
	m.selectFinding(29)
	view := ansi.Strip(m.View())
	if !strings.Contains(view, "RESULT-29") || !strings.Contains(view, "▶") {
		t.Fatalf("selected result hidden by header in small terminal:\n%s", view)
	}
	next, _ := m.updateProjectResults("pgup")
	m = next.(model)
	if m.findingIndex >= 29 {
		t.Fatal("list page navigation did not move selection")
	}
}
func TestListLabelCannotAddTerminalRows(t *testing.T) {
	row := renderListRow("service\n\x1b[2Jother\rname", true, 60)
	if strings.Contains(row, "\x1b[2J") || strings.Count(row, "\n") != 1 {
		t.Fatalf("label changed terminal layout: %q", row)
	}
}
