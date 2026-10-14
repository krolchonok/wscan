package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestInputCursorEditsInsideUnicodeText(t *testing.T) {
	m := model{screen: "input", inputAction: "guided-scope", input: "абв"}
	steps := []struct {
		key  tea.KeyMsg
		want string
	}{
		{tea.KeyMsg{Type: tea.KeyLeft}, "абв"},
		{tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("XY"), Paste: true}, "абXYв"},
		{tea.KeyMsg{Type: tea.KeyBackspace}, "абXв"},
		{tea.KeyMsg{Type: tea.KeyDelete}, "абX"},
		{tea.KeyMsg{Type: tea.KeyRight}, "абX"},
		{tea.KeyMsg{Type: tea.KeyEnd}, "абX"},
		{tea.KeyMsg{Type: tea.KeyDelete}, "абX"},
		{tea.KeyMsg{Type: tea.KeyHome}, "абX"},
		{tea.KeyMsg{Type: tea.KeyBackspace}, "абX"},
		{tea.KeyMsg{Type: tea.KeyDelete}, "бX"},
		{tea.KeyMsg{Type: tea.KeySpace}, " бX"},
		{tea.KeyMsg{Type: tea.KeyCtrlU}, ""},
	}
	for i, step := range steps {
		next, _ := m.Update(step.key)
		m = next.(model)
		if m.input != step.want {
			t.Fatalf("step %d: input = %q, want %q", i, m.input, step.want)
		}
	}
}

func TestInputCursorRemainsVisibleInLongPrefilledField(t *testing.T) {
	m := model{screen: "guided-scan"}
	m.startInput("guided-scope")
	m.input = strings.Repeat("192.0.2.10 ", 30)
	for _, key := range []tea.KeyType{tea.KeyEnd, tea.KeyLeft, tea.KeyHome} {
		next, _ := m.Update(tea.KeyMsg{Type: key})
		m = next.(model)
		line := m.inputLine(20)
		if !strings.Contains(line, "▏") || ansi.StringWidth(line) > 20 {
			t.Fatalf("cursor not visible within field: %q", line)
		}
	}
	// Starting another prefilled field resets the cursor to the end.
	m.startInput("guided-scope")
	m.input = "192.0.2.1"
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("0")})
	if next.(model).input != "192.0.2.10" {
		t.Fatal("new prefilled field retained the previous cursor position")
	}
}
