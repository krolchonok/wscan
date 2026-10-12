package tui

import (
	"context"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"time"
	"wscan/internal/domain"
	"wscan/internal/storage"
)

type resultDeleted struct {
	generation int
	projectID  int64
	findings   []domain.Finding
	count      int
	err        error
}

func resultSelectionKey(f domain.Finding) string {
	if f.TemplateID == "ui/coercion-summary" {
		f.MatcherName = ""
	}
	return storage.FindingKey(f)
}

func (m model) resultDeleteMembers(f domain.Finding) []domain.Finding {
	if f.TemplateID != "ui/coercion-summary" {
		return []domain.Finding{f}
	}
	var out []domain.Finding
	for _, v := range m.resultsRawFindings() {
		if v.Target == f.Target && coercionResult(v) {
			out = append(out, v)
		}
	}
	return out
}
func (m model) requestResultDelete(visible bool) (tea.Model, tea.Cmd) {
	rows := m.filteredProjectFindings()
	var chosen []domain.Finding
	for _, f := range rows {
		if visible || m.projectResultsSelected[resultSelectionKey(f)] {
			chosen = append(chosen, f)
		}
	}
	if len(chosen) == 0 && m.findingDetail != nil {
		chosen = append(chosen, *m.findingDetail)
	}
	if len(chosen) == 0 {
		m.message = "Нет результатов для удаления"
		return m, nil
	}
	m.resultDeleteFindings = nil
	for _, f := range chosen {
		m.resultDeleteFindings = append(m.resultDeleteFindings, m.resultDeleteMembers(f)...)
	}
	m.resultDeleteCount = len(chosen)
	m.resultDeleteGeneration++
	m.resultDeleteConfirm = true
	return m, nil
}
func (m model) confirmResultDelete(key string) (tea.Model, tea.Cmd) {
	if m.resultDeleting {
		return m, nil
	}
	switch key {
	case "esc", "q", "n":
		m.resultDeleteConfirm = false
		m.resultDeleteFindings = nil
		return m, nil
	case "enter", "y":
		if m.store == nil {
			m.message = "База результатов недоступна"
			m.resultDeleteConfirm = false
			return m, nil
		}
		fs := append([]domain.Finding(nil), m.resultDeleteFindings...)
		projectID := m.current.ID
		generation := m.resultDeleteGeneration
		store := m.store
		parent := m.ctx
		if parent == nil {
			parent = context.Background()
		}
		m.resultDeleting = true
		return m, func() tea.Msg {
			ctx, cancel := context.WithTimeout(parent, 10*time.Second)
			defer cancel()
			count, err := store.DeleteFindings(ctx, projectID, fs)
			return resultDeleted{generation: generation, projectID: projectID, findings: fs, count: count, err: err}
		}
	}
	return m, nil
}
func (m model) applyResultDeleted(msg resultDeleted) (tea.Model, tea.Cmd) {
	if msg.projectID != m.current.ID || msg.generation != m.resultDeleteGeneration {
		return m, nil
	}
	m.resultDeleting = false
	m.resultDeleteConfirm = false
	if msg.err != nil {
		m.message = "Не удалось удалить результаты: " + msg.err.Error()
		return m, nil
	}
	snapshot := storage.FindingDeleteSnapshot(msg.findings)
	remove := func(fs []domain.Finding) []domain.Finding {
		out := make([]domain.Finding, 0, len(fs))
		for _, f := range fs {
			if !storage.FindingInDeleteSnapshot(f, snapshot) {
				out = append(out, f)
			}
		}
		return out
	}
	for _, h := range m.inventory {
		h.findings = remove(h.findings)
	}
	for i := range m.history {
		m.history[i].Findings = remove(m.history[i].Findings)
	}
	for _, j := range m.jobs {
		if j.projectID == m.current.ID && j.result != nil {
			j.result.Findings = remove(j.result.Findings)
			j.findings = len(groupedProjectResults(orderedResults(j.result.Findings)))
		}
	}
	m.resultDeleteFindings = nil
	m.projectResultsSelected = nil
	m.findingPane = 0
	m.refreshProjectResultSelection()
	m.message = fmt.Sprintf("Удалено сохранённых детектов: %d. Новая проверка может обнаружить их снова.", msg.count)
	return m, nil
}
