package tui

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"strings"
	"wscan/internal/domain"
)

func resultPreview(f domain.Finding) string {
	if f.TemplateID == "ui/coercion-summary" {
		return f.Description
	}
	text := findingEvidenceText(f.Evidence, false)
	if text == "" {
		text = f.Description
	}
	if text == "" {
		text = resultExplanation(f)
	}
	return strings.Join(strings.Fields(ansi.Strip(text)), " ")
}
func (m model) viewProjectResults(w int) string {
	if m.resultDeleteConfirm {
		body := headingStyle.Render("Удалить результаты?") + fmt.Sprintf("\n\nВыбрано строк: %d\n\nУдалятся сохранённые детекты и их старые копии в этом проекте.\nДля сводки Coerce удалятся также входящие в неё события.\n\n", m.resultDeleteCount)
		if m.resultDeleting {
			body += "Удаляю…"
		} else {
			body += "Enter / y — удалить · Esc / n — отменить"
		}
		return m.renderPanel(w, body)
	}
	if m.findingPane == 1 && m.splitResultDetails(w) {
		return m.viewSplitResultDetails(w)
	}
	rows := m.filteredProjectFindings()
	body := m.resultsHeader(w)
	if m.findingPane == 1 && m.findingDetail != nil {
		lines := m.projectResultDetailLines(max(1, w-6))
		visible := m.resultDetailRows(w)
		offset := min(m.findingOffset, max(0, len(lines)-visible))
		body = m.resultDetailHeader(w) + strings.Join(lines[offset:min(len(lines), offset+visible)], "\n")
		body += fmt.Sprintf("\nСтроки %d–%d из %d · ↑/↓ PgUp/PgDn", offset+1, min(len(lines), offset+visible), len(lines))
		return m.renderPanel(w, body)
	}
	body = m.resultListHeader(w)
	if len(rows) == 0 {
		body += "Нет результатов по выбранному фильтру.\nНаходка не выбрана. Нажми c, чтобы сбросить фильтр."
		return m.renderPanel(w, body)
	}
	visible := m.resultListRows(w)
	lo, hi := windowRange(m.findingIndex, len(rows), visible)
	body += moreLine(lo, true)
	for i := lo; i < hi; i++ {
		f := rows[i]
		mark := "[ ] "
		if m.projectResultsSelected[resultSelectionKey(f)] {
			mark = "[✓] "
		}
		body += renderFindingTextRow(f, mark+projectResultLabel(f), i == m.findingIndex, w-4)
		body += "    " + ansi.Truncate(resultPreview(f), max(1, w-10), "…") + "\n"
	}
	body += moreLine(len(rows)-hi, false)
	return m.renderPanel(w, body)
}

func (m model) projectResultDetailLines(w int) []string {
	if m.findingDetail == nil {
		return []string{"Находка не выбрана"}
	}
	if m.findingRaw {
		return m.findingLines(w)
	}
	f := *m.findingDetail
	body := ""
	switch m.findingSection {
	case 1:
		evidence := strings.TrimSpace(f.Evidence)
		if table, ok := smbFindingTable(f, w); ok {
			evidence = table
		} else if evidence != "" {
			evidence = findingEvidenceText(evidence, false)
		} else if pretty, ok := prettyJSON(f.Response); ok {
			evidence = pretty
		}
		if evidence == "" {
			evidence = "Доказательства не сохранены. Полный отчёт доступен по r."
		}
		body = "Что обнаружено\n\n" + evidence
	case 2:
		if m.findingRemediation != "" {
			body = "Что исправить\n\n" + strings.TrimSpace(m.findingRemediation)
		} else {
			body = "Для этой проверки нет сохранённых рекомендаций."
		}
		if m.findingImpact != "" {
			body += "\n\nВозможные последствия\n" + strings.TrimSpace(m.findingImpact)
		}
		if len(f.References) > 0 {
			body += "\n\nСсылки\n" + strings.Join(f.References, "\n")
		}
	default:
		address := f.MatchedAt
		if address == "" || len(strings.Fields(address)) > 1 {
			address = projectResultLocation(f)
		}
		body = resultTitle(f) + "\n\n"
		if credentials := findingCredentialSummary(f); credentials != "" {
			body += "Учётные данные совпавшей проверки\n" + credentials + "\n\n"
		} else if f.TemplateID == "smb-default-login" {
			body += "Учётные данные не сохранены в этом результате. Повторная проверка сохранит найденную пару.\n\n"
		}
		body += "Адрес: " + address + "\nТип: " + resultClass(f)
		if resultClass(f) == "Риск" {
			body += " · " + strings.ToUpper(domain.EffectiveSeverity(f))
		}
		if !f.Time.IsZero() {
			body += "\nВремя: " + f.Time.Local().Format("02.01.2006 15:04:05")
		}
		body += "\n\n" + resultExplanation(f)
		if f.Description != "" {
			body += "\n\nОписание\n" + f.Description
		}
	}

	return strings.Split(ansi.Wrap(ansi.Strip(body), max(1, w), ""), "\n")
}

func (m model) resultsHeader(w int) string {
	return headingStyle.Render(ansi.Truncate("Результаты · "+singleLineText(m.resultsScopeLabel()), max(1, w-4), "…")) + "\n" + ansi.Truncate(singleLineText(m.projectResultsSummary()), max(1, w-4), "…") + "\n\n"
}
func (m model) resultListHeader(w int) string {
	return m.resultsHeader(w)
}
func (m model) resultListRows(w int) int {
	return max(1, (m.bodyHeight()-2-lipgloss.Height(m.resultListHeader(w))-2)/2)
}
func (m model) resultDetailRows(w int) int {
	width := m.resultDetailWidth(w)
	return max(1, m.bodyHeight()-2-lipgloss.Height(m.resultDetailHeader(width))-1)
}

func (m model) resultDetailHeader(w int) string {
	width := max(1, w-4)
	title := fmt.Sprintf("Находка %d / %d", m.findingIndex+1, len(m.filteredProjectFindings()))
	body := headingStyle.Render(ansi.Truncate(title, width, "…")) + "\n"
	labels := []string{"Обзор", "Доказательства", "Рекомендации"}
	if m.findingRaw {
		body += headingStyle.Render("Технический отчёт") + "\n"
	} else {
		for i, label := range labels {
			if i == m.findingSection {
				labels[i] = "[" + label + "]"
			}
		}
		body += ansi.Wrap(strings.Join(labels, " · "), width, "") + "\n"
	}
	body += "\n"
	return body
}

func (m model) splitResultDetails(w int) bool { return w >= 88 }

func resultListWidth(w int) int { return min(52, max(30, w/3)) }

func (m model) resultDetailWidth(w int) int {
	if m.findingPane == 1 && m.splitResultDetails(w) {
		return w - resultListWidth(w)
	}
	return w
}

func (m model) viewSplitResultDetails(w int) string {
	left, right := resultListWidth(w), m.resultDetailWidth(w)
	height := max(1, m.bodyHeight()-2)
	rows := m.filteredProjectFindings()
	body := headingStyle.Render("Найдено") + fmt.Sprintf(" · %d\n", len(rows))
	body += ansi.Truncate(singleLineText(m.resultsScopeLabel()), left-4, "…") + "\n\n"
	lo, hi := windowRange(m.findingIndex, len(rows), max(1, height-5))
	body += moreLine(lo, true)
	for i := lo; i < hi; i++ {
		mark := ""
		if m.projectResultsSelected[resultSelectionKey(rows[i])] {
			mark = "✓ "
		}
		body += renderFindingTextRow(rows[i], mark+resultLabel(rows[i]), i == m.findingIndex, left-4)
	}
	body += moreLine(len(rows)-hi, false)
	lines := m.projectResultDetailLines(max(1, right-6))
	visible := m.resultDetailRows(w)
	offset := min(m.findingOffset, max(0, len(lines)-visible))
	detail := m.resultDetailHeader(right) + strings.Join(lines[offset:min(len(lines), offset+visible)], "\n")
	detail += fmt.Sprintf("\nСтроки %d–%d из %d", offset+1, min(len(lines), offset+visible), len(lines))
	return lipgloss.JoinHorizontal(lipgloss.Top,
		renderColumn(body, left-4, height, !m.findingDetailFocus),
		renderColumn(detail, right-4, height, m.findingDetailFocus))
}
