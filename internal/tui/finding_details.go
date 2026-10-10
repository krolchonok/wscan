package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
)

func (m model) deskFindings() []domain.Finding {
	host := m.currentHost()
	services := m.servicesFor(host)
	if m.serviceIndex >= 0 && m.serviceIndex < len(services) {
		return m.findingsForService(host, services[m.serviceIndex])
	}
	return m.findingsFor(host)
}

func (m *model) openFinding() bool {
	if !m.selectFinding(m.findingIndex) {
		return false
	}
	m.findingRaw = false
	m.findingPane = 0
	m.screen = "finding-details"
	return true
}

func (m *model) selectFinding(index int) bool {
	findings := m.deskFindings()
	if len(findings) == 0 {
		return false
	}
	m.findingIndex = max(0, min(index, len(findings)-1))
	f := findings[m.findingIndex]
	m.findingDetail = &f
	m.findingMetadata = false
	m.findingTemplatePath = ""
	m.findingImpact = ""
	m.findingRemediation = ""
	m.findingClassified = ""
	m.enrichFinding()
	m.findingOffset = 0
	return true
}

func (m *model) enrichFinding() {
	if m.findingDetail == nil || m.cat == nil {
		return
	}
	meta, ok := m.cat.Metadata(m.findingDetail.TemplateID)
	if !ok {
		return
	}
	m.findingTemplatePath = meta.Path
	m.findingImpact = meta.Impact
	m.findingRemediation = meta.Remediation
	m.findingClassified = meta.Classification
	if m.findingDetail.Description == "" && meta.Description != "" {
		m.findingDetail.Description = meta.Description
		m.findingMetadata = true
	}
	if len(m.findingDetail.References) == 0 {
		m.findingDetail.References = meta.References
	}
}

func (m model) findingLines(width int) []string {
	f := m.findingDetail
	if f == nil {
		return []string{"Находка не выбрана"}
	}
	body := fmt.Sprintf("%s\n\nТип: %s\nАдрес: %s\nВремя: %s\n\n%s\n", resultTitle(*f), resultClass(*f), f.MatchedAt, f.Time.Local().Format("02.01.2006 15:04:05"), resultExplanation(*f))
	if resultClass(*f) == "Риск" {
		severity := strings.ToUpper(f.Severity)
		if f.Severity == "unknown" || f.Severity == "info" {
			severity = "не оценена"
		}
		body += "Критичность: " + severity + "\n"
	}
	for _, line := range smbSummary([]domain.Finding{*f}) {
		body += line + "\n"
	}
	if m.findingRaw {
		body += fmt.Sprintf("\nШаблон: %s\nЦель: %s\nВоздействие: %s\n", f.TemplateID, f.Target, f.Risk)
	}
	if m.findingRaw && f.Protocol != "" {
		body += "Протокол: " + f.Protocol + "\n"
	}
	if m.findingRaw && f.MatcherName != "" {
		body += "Матчер: " + f.MatcherName + "\n"
	}
	showMeta := m.findingRaw || resultClass(*f) == "Риск"
	if showMeta && f.Description != "" {
		label := "ОПИСАНИЕ"
		if m.findingMetadata {
			label = "ОПИСАНИЕ ПРОВЕРКИ ИЗ ЛОКАЛЬНОЙ БИБЛИОТЕКИ"
		}
		body += "\n" + label + "\n" + f.Description + "\n"
	}
	if showMeta && m.findingClassified != "" {
		body += "\nКЛАССИФИКАЦИЯ\n" + m.findingClassified + "\n"
	}
	if showMeta && m.findingImpact != "" {
		body += "\nВОЗДЕЙСТВИЕ\n" + strings.TrimSpace(m.findingImpact) + "\n"
	}
	if showMeta && m.findingRemediation != "" {
		body += "\nРЕКОМЕНДАЦИЯ\n" + strings.TrimSpace(m.findingRemediation) + "\n"
	}
	if m.findingRaw && m.findingTemplatePath != "" {
		body += "\nФайл проверки: " + m.findingTemplatePath + "\n"
	}
	evidence := f.Evidence
	structured := false
	if !m.findingRaw {
		if table, ok := smbFindingTable(*f, width); ok {
			evidence, structured = table, true
		}
	}
	if evidence == "" {
		if pretty, ok := prettyJSON(f.Response); ok {
			evidence = pretty
		}
	}
	if evidence != "" {
		label := "ЧТО ОБНАРУЖЕНО"
		if resultClass(*f) == "Ошибка" {
			label = "ОШИБКА ПРОВЕРКИ"
		} else if m.findingRaw {
			label = "ТЕХНИЧЕСКИЕ ДОКАЗАТЕЛЬСТВА"
		}
		if !structured {
			evidence = findingEvidenceText(evidence, m.findingRaw)
		}
		body += "\n" + label + "\n" + evidence + "\n"
	} else {
		body += "\nПроверка зарегистрировала совпадение; извлечённые значения не сохранены.\n"
	}
	if len(f.References) > 0 {
		body += "\nССЫЛКИ\n" + strings.Join(f.References, "\n") + "\n"
	}
	if m.findingRaw && f.Request != "" {
		body += "\nЗАПРОС\n" + f.Request + "\n"
	}
	if m.findingRaw && f.Response != "" {
		body += "\nОТВЕТ\n" + f.Response + "\n"
	}
	if m.findingRaw && f.Request == "" && f.Response == "" {
		body += "\nВ сохранённом результате нет запроса и ответа. Новые сканы сохраняют эти поля, если движок их возвращает.\n"
	}
	if !m.findingRaw {
		body += "\nr — раскрыть шаблон, описание, запрос и полный ответ.\n"
	}
	body = ansi.Strip(strings.ReplaceAll(body, "\r\n", "\n"))
	return strings.Split(ansi.Wrap(body, max(1, width), ""), "\n")
}

// findingEvidenceText keeps matcher implementation details out of the normal
// finding view. The exact DSL/XPath expression remains available in raw mode.
func findingEvidenceText(evidence string, raw bool) string {
	evidence = strings.TrimSpace(evidence)
	if raw {
		return evidence
	}
	for _, prefix := range []string{"dsl matched:", "xpath matched:"} {
		if strings.HasPrefix(strings.ToLower(evidence), prefix) {
			if i := strings.IndexByte(evidence, ';'); i >= 0 {
				evidence = strings.TrimSpace(evidence[i+1:])
			} else {
				return "Шаблон подтвердил условие совпадения."
			}
			break
		}
	}
	for _, prefix := range []string{"Данные JSON:", "JSON:", "json:"} {
		if strings.HasPrefix(strings.ToLower(evidence), strings.ToLower(prefix)) {
			payload := strings.TrimSpace(evidence[len(prefix):])
			if pretty, ok := prettyJSON(payload); ok {
				return "Данные JSON:\n" + pretty
			}
			evidence = "Данные JSON: " + payload
			break
		}
	}
	if pretty, ok := prettyJSON(evidence); ok {
		evidence = pretty
	}
	if evidence == "" {
		return "Шаблон подтвердил условие совпадения."
	}
	return evidence
}

func prettyJSON(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || !json.Valid([]byte(value)) {
		return "", false
	}
	var out bytes.Buffer
	if err := json.Indent(&out, []byte(value), "", "  "); err != nil {
		return "", false
	}
	return out.String(), true
}

func (m model) findingRows() int { return max(1, m.bodyHeight()-4) }

func findingPanelWidths(width int) (int, int) {
	available := max(2, width-8)
	left := min(52, max(20, available*42/100))
	left = min(left, max(1, available/2))
	return left, max(1, available-left)
}

func (m model) updateFindingDetails(key string) (tea.Model, tea.Cmd) {
	rows := m.findingRows()
	_, rightWidth := findingPanelWidths(m.width)
	last := max(0, len(m.findingLines(rightWidth))-rows)
	switch key {
	case "left":
		m.findingPane = 0
	case "right", "enter":
		m.findingPane = 1
	case "tab", "shift+tab":
		m.findingPane = 1 - m.findingPane
	case "r":
		m.findingRaw = !m.findingRaw
		m.findingOffset = 0
	case "esc", "q":
		m.screen = "desk"
	case "up", "k":
		if m.findingPane == 0 {
			m.selectFinding(m.findingIndex - 1)
		} else {
			m.findingOffset = max(0, m.findingOffset-1)
		}
	case "down", "j":
		if m.findingPane == 0 {
			m.selectFinding(m.findingIndex + 1)
		} else {
			m.findingOffset = min(last, m.findingOffset+1)
		}
	case "pgup":
		m.findingOffset = max(0, m.findingOffset-rows)
	case "pgdown":
		m.findingOffset = min(last, m.findingOffset+rows)
	case "home":
		if m.findingPane == 0 {
			m.selectFinding(0)
		} else {
			m.findingOffset = 0
		}
	case "end":
		if m.findingPane == 0 {
			m.selectFinding(len(m.deskFindings()) - 1)
		} else {
			m.findingOffset = last
		}
	}
	return m, nil
}

func (m model) viewFindingDetails(w int) string {
	leftWidth, rightWidth := findingPanelWidths(w)
	height := max(1, m.bodyHeight()-2)
	findings := m.deskFindings()
	var list strings.Builder
	list.WriteString(headingStyle.Render(fmt.Sprintf("РЕЗУЛЬТАТЫ %d/%d", min(m.findingIndex+1, len(findings)), len(findings))) + "\n")
	list.WriteString(mutedStyle.Render("↑/↓ — выбрать · → — текст") + "\n\n")
	visible := max(1, height-5)
	lo, hi := windowRange(m.findingIndex, len(findings), visible)
	list.WriteString(moreLine(lo, true))
	for i := lo; i < hi; i++ {
		f := findings[i]
		list.WriteString(renderListRow(resultLabel(f), i == m.findingIndex, leftWidth))
	}
	list.WriteString(moreLine(len(findings)-hi, false))
	lines := m.findingLines(rightWidth)
	rows := m.findingRows()
	offset := min(m.findingOffset, max(0, len(lines)-rows))
	end := min(len(lines), offset+rows)
	body := headingStyle.Render("ПОДРОБНОСТИ") + fmt.Sprintf(" · %d–%d/%d\n", offset+1, end, len(lines)) + mutedStyle.Render("PgUp/PgDn — прокрутка · r — технические данные") + "\n" + strings.Join(lines[offset:end], "\n")
	return lipgloss.JoinHorizontal(lipgloss.Top,
		colBoxStyle(leftWidth, height, m.findingPane == 0).Render(list.String()),
		colBoxStyle(rightWidth, height, m.findingPane == 1).Render(body))
}
