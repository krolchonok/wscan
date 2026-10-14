package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func (m model) inputPosition() int {
	length := len([]rune(m.input))
	return length - min(max(0, m.inputOffset), length)
}

func (m *model) editInput(key tea.KeyMsg) bool {
	runes := []rune(m.input)
	position := m.inputPosition()
	m.inputOffset = len(runes) - position
	switch key.Type {
	case tea.KeyLeft, tea.KeyCtrlB:
		m.inputOffset = min(len(runes), m.inputOffset+1)
	case tea.KeyRight, tea.KeyCtrlF:
		m.inputOffset = max(0, m.inputOffset-1)
	case tea.KeyHome, tea.KeyCtrlA:
		m.inputOffset = len(runes)
	case tea.KeyEnd, tea.KeyCtrlE:
		m.inputOffset = 0
	case tea.KeyBackspace, tea.KeyCtrlH:
		if position > 0 {
			m.input = string(runes[:position-1]) + string(runes[position:])
		}
	case tea.KeyDelete:
		if position < len(runes) {
			m.input = string(runes[:position]) + string(runes[position+1:])
			m.inputOffset--
		}
	case tea.KeyCtrlU:
		m.input, m.inputOffset = "", 0
	case tea.KeySpace:
		m.input = string(runes[:position]) + " " + string(runes[position:])
	case tea.KeyRunes:
		m.input = string(runes[:position]) + string(key.Runes) + string(runes[position:])
	default:
		return false
	}
	return true
}

func (m model) inputLine(width int) string {
	width = max(1, width)
	runes := []rune(m.input)
	position := m.inputPosition()
	before := strings.ReplaceAll(string(runes[:position]), "\n", " ")
	after := strings.ReplaceAll(string(runes[position:]), "\n", " ")
	beforeWidth := ansi.StringWidth(before)
	if beforeWidth >= width {
		before = ansi.Cut(before, beforeWidth-(width-1), beforeWidth)
	}
	return ansi.Truncate(before+"▏"+after, width, "")
}
