package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"strings"
)

func (m model) helpLines(w int) []string {
	context := m
	context.screen = m.helpReturn
	body := screenTitle(m.helpReturn) + "\n\nНА ЭТОМ ЭКРАНЕ\n" + strings.ReplaceAll(strings.ReplaceAll(context.footer(), "   ", "\n"), " · ", "\n")
	body += "\n\nОБЩЕЕ\n0 — разведка сети\n1–5 — рабочие разделы из списков\nEnter — открыть / выполнить\nEsc — назад / отменить\ng — задачи\n? — помощь для текущего экрана\nCtrl+C — завершить приложение"
	return strings.Split(ansi.Wrap(ansi.Strip(body), max(1, w), ""), "\n")
}
func (m model) updateHelp(key string) (tea.Model, tea.Cmd) {
	rows := max(1, m.bodyHeight()-4)
	last := max(0, len(m.helpLines(max(1, m.width-4)))-rows)
	switch key {
	case "esc", "enter", "q":
		m.screen = m.helpReturn
	case "up", "k":
		m.helpOffset = max(0, m.helpOffset-1)
	case "down", "j":
		m.helpOffset = min(last, m.helpOffset+1)
	case "pgup":
		m.helpOffset = max(0, m.helpOffset-rows)
	case "pgdown":
		m.helpOffset = min(last, m.helpOffset+rows)
	case "home":
		m.helpOffset = 0
	case "end":
		m.helpOffset = last
	}
	return m, nil
}
func (m model) viewHelp(w int) string {
	lines := m.helpLines(max(1, w-4))
	rows := max(1, m.bodyHeight()-4)
	offset := min(m.helpOffset, max(0, len(lines)-rows))
	body := headingStyle.Render("Клавиши · ↑/↓ прокрутка") + "\n\n" + strings.Join(lines[offset:min(len(lines), offset+rows)], "\n")
	return m.renderPanel(w, body)
}
func runStatusLabel(status string) string {
	switch status {
	case "completed":
		return "завершён"
	case "running":
		return "выполняется"
	case "failed":
		return "ошибка"
	case "cancelled", "canceled":
		return "отменён"
	default:
		return status
	}
}
