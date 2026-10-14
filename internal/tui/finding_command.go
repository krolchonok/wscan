package tui

import (
	"encoding/base64"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/commandgen"
	"wscan/internal/domain"
)

func findingMSFCommand(f domain.Finding) (string, string, bool) {
	return commandgen.MSF(f)
}

func (m model) deskCommandAvailable() bool {
	if m.focusCol != 2 || m.currentHost() == "" {
		return false
	}
	findings := m.deskFindings()
	if m.findingIndex < 0 || m.findingIndex >= len(findings) {
		return false
	}
	_, _, ok := findingMSFCommand(findings[m.findingIndex])
	return ok
}

func (m model) openDeskCommand() (tea.Model, tea.Cmd) {
	if !m.deskCommandAvailable() {
		m.message = "Выделите MS17-010 или MS12-020 в колонке результатов и нажмите m."
		return m, nil
	}
	if m.openFinding() {
		m.findingSection, m.findingOffset = 3, 0
		m.findingRaw, m.findingDetailFocus = false, true
		m.message = "y — скопировать команду · Esc — вернуться к хостам и портам"
	}
	return m, nil
}

func (m model) findingSections() []string {
	labels := []string{"Обзор", "Доказательства", "Рекомендации"}
	if m.findingDetail != nil {
		if _, _, ok := findingMSFCommand(*m.findingDetail); ok {
			labels = append(labels, "Команда")
		}
	}
	return labels
}

func (m model) findingCommandText() string {
	if m.findingDetail == nil {
		return "Для этой находки нет команды."
	}
	command, explanation, ok := findingMSFCommand(*m.findingDetail)
	if !ok {
		return "Для этой находки нет команды."
	}
	text := "Команда для msfconsole\n\n" + explanation + "\n\n" + command
	if m.clientSource != "web-terminal" {
		text += "\n\ny — скопировать одной строкой (терминал с поддержкой OSC 52)."
	}
	return text
}

type findingCommandCopied struct{ err error }

func (m model) copyFindingCommand() (tea.Model, tea.Cmd) {
	if m.findingDetail == nil {
		return m, nil
	}
	command, _, ok := findingMSFCommand(*m.findingDetail)
	if !ok {
		return m, nil
	}
	if m.clientSource == "web-terminal" {
		m.message = "Выделите команду и скопируйте её средствами браузера."
		return m, nil
	}
	return m, func() tea.Msg {
		// OSC 52 copies text; it does not execute the generated command.
		_, err := fmt.Fprint(os.Stdout, "\x1b]52;c;"+base64.StdEncoding.EncodeToString([]byte(command))+"\a")
		return findingCommandCopied{err: err}
	}
}
