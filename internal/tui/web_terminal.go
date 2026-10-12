package tui

import (
	"context"
	"fmt"
	"io"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/app"
)

// WebTerminal runs the existing TUI against a frame/key transport. Every legacy
// form, browser and console remains available without a second implementation.
type WebTerminal struct {
	mu      sync.RWMutex
	frame   string
	err     error
	closed  bool
	program *tea.Program
	cancel  context.CancelFunc
	done    chan struct{}
}
type frameModel struct {
	model    model
	terminal *WebTerminal
}

func (m frameModel) Init() tea.Cmd { return m.model.Init() }
func (m frameModel) View() string  { return m.model.View() }
func (m frameModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := m.model.Update(msg)
	next, ok := updated.(model)
	if !ok {
		return m, cmd
	}
	m.model = next
	m.terminal.mu.Lock()
	m.terminal.frame = next.View()
	m.terminal.mu.Unlock()
	return m, cmd
}
func StartWebTerminal(parent context.Context, service *app.Service, dir string, width, height int) (*WebTerminal, error) {
	ctx, cancel := context.WithCancel(parent)
	terminal := &WebTerminal{cancel: cancel, done: make(chan struct{})}
	m := model{clientSource: "web-terminal", ctx: ctx, store: service.Store, cat: service.Catalog, scanner: service.Scanner, shared: service, guided: true, appDir: dir, screen: "projects", width: max(55, min(200, width)), height: max(18, min(60, height)), jobEvents: make(chan jobEvent, 16), message: "Enter — открыть проект; n — создать. 0 — обзор открытого проекта."}
	if err := m.reload(); err != nil {
		cancel()
		return nil, err
	}
	terminal.frame = m.View()
	terminal.program = tea.NewProgram(frameModel{model: m, terminal: terminal}, tea.WithContext(ctx), tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithoutRenderer(), tea.WithoutSignalHandler())
	go func() {
		_, err := terminal.program.Run()
		terminal.mu.Lock()
		terminal.err = err
		terminal.closed = true
		terminal.mu.Unlock()
		cancel()
		close(terminal.done)
	}()
	return terminal, nil
}
func (t *WebTerminal) Frame() (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.frame, t.closed
}
func (t *WebTerminal) Key(key string) error {
	t.mu.RLock()
	closed := t.closed
	t.mu.RUnlock()
	if closed {
		return fmt.Errorf("сеанс TUI завершён")
	}
	mapping := map[string]tea.KeyType{"Enter": tea.KeyEnter, "Escape": tea.KeyEsc, "ArrowUp": tea.KeyUp, "ArrowDown": tea.KeyDown, "ArrowLeft": tea.KeyLeft, "ArrowRight": tea.KeyRight, "Tab": tea.KeyTab, "Backspace": tea.KeyBackspace, "Delete": tea.KeyDelete, "Home": tea.KeyHome, "End": tea.KeyEnd, "PageUp": tea.KeyPgUp, "PageDown": tea.KeyPgDown, "ctrl+u": tea.KeyCtrlU, "ctrl+c": tea.KeyCtrlC, "shift+tab": tea.KeyShiftTab}
	if kind, ok := mapping[key]; ok {
		t.program.Send(tea.KeyMsg{Type: kind})
		return nil
	}
	runes := []rune(key)
	if len(runes) == 0 || len(runes) > 4096 {
		return fmt.Errorf("некорректный ввод")
	}
	t.program.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: runes})
	return nil
}
func (t *WebTerminal) Resize(width, height int) {
	t.program.Send(tea.WindowSizeMsg{Width: max(55, min(200, width)), Height: max(18, min(60, height))})
}
func (t *WebTerminal) Close() { t.cancel(); <-t.done }
