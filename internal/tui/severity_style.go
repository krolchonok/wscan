package tui

import (
	"github.com/charmbracelet/lipgloss"
	"wscan/internal/domain"
)

func severityColor(severity string) lipgloss.Color {
	colors := map[string]string{
		"critical": "#FF5555", "high": "#FF9E64", "medium": "#E5C07B",
		"low": "#98C379", "info": "#61AFEF", "unknown": "#82949A", "error": "#FF5555",
	}
	if color, ok := colors[severity]; ok {
		return lipgloss.Color(color)
	}
	return lipgloss.Color("#82949A")
}

func renderFindingRow(f domain.Finding, selected bool, width int) string {
	severity := domain.EffectiveSeverity(f)
	if resultClass(f) == "Ошибка" {
		severity = "error"
	}
	color := severityColor(severity)
	return renderStyledListRow(resultLabel(f), selected, width,
		rowStyle.Foreground(color), selectedRowStyle.Foreground(color).Background(lipgloss.Color("#203638")))
}
