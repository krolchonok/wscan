package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
	"wscan/internal/domain"
	"wscan/internal/nse"
)

func TestVNCWarningIsCriticalInNewAndSavedResults(t *testing.T) {
	const evidence = "Protocol version: 3.8\nWARNING: Server does not require authentication"
	fresh := nseFinding("127.0.0.1", nse.ScriptResult{ScriptID: "vnc-info", Port: 5900, Output: evidence})
	if fresh.Severity != "critical" {
		t.Fatalf("new severity: %s", fresh.Severity)
	}
	old := fresh
	old.Severity = "info"
	if resultClass(old) != "Риск" || resultRank(old) != 0 || !strings.Contains(resultLabel(old), "КРИТИЧЕСКИЙ") {
		t.Fatalf("old result remains informational: %s", resultLabel(old))
	}
	lines := strings.Join((model{findingDetail: &old}).findingLines(120), "\n")
	if !strings.Contains(lines, "CRITICAL") || !strings.Contains(lines, "не подтверждает") {
		t.Fatalf("missing severity or negotiation limitation: %s", lines)
	}
	protected := nseFinding("127.0.0.1", nse.ScriptResult{ScriptID: "vnc-info", Output: "Security types: VNC Authentication (2)"})
	if resultClass(protected) != "Сведения" {
		t.Fatal("ordinary VNC discovery promoted to risk")
	}
}

func TestFindingRowsHaveDistinctColorsAndFitWidth(t *testing.T) {
	oldProfile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(oldProfile) })
	seen := map[lipgloss.Color]bool{}
	for _, severity := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		color := severityColor(severity)
		if seen[color] {
			t.Fatalf("duplicate severity color: %s", severity)
		}
		seen[color] = true
		for _, selected := range []bool{false, true} {
			row := renderFindingRow(domain.Finding{Name: strings.Repeat("long title ", 30), Severity: severity}, selected, 55)
			if !strings.Contains(row, "\x1b[") || ansi.StringWidth(strings.TrimSuffix(row, "\n")) > 55 {
				t.Fatalf("row lacks color or overflows: %q", row)
			}
			if selected && !strings.Contains(ansi.Strip(row), "▶") {
				t.Fatal("selection marker missing")
			}
		}
	}
}
