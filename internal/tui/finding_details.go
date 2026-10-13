package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
)

func (m model) deskFindings() []domain.Finding {
	if m.screen == "project-results" {
		return m.filteredProjectFindings()
	}
	host := m.currentHost()
	services := m.servicesFor(host)
	if m.serviceIndex >= 0 && m.serviceIndex < len(services) {
		return m.findingsForService(host, services[m.serviceIndex])
	}
	if m.selectedPortMissing() {
		return nil
	}
	return m.findingsFor(host)
}

func (m *model) openFinding() bool {
	if !m.selectFinding(m.findingIndex) {
		return false
	}
	selected := *m.findingDetail
	scope := resultScope{host: m.currentHost()}
	if services := m.servicesFor(scope.host); m.serviceIndex >= 0 && m.serviceIndex < len(services) {
		service := services[m.serviceIndex]
		scope.service = &service
	}
	m.openScopedResults(scope)
	m.projectResultsFilter = "all"
	for i, f := range m.filteredProjectFindings() {
		if resultSelectionKey(f) == resultSelectionKey(selected) {
			m.selectFinding(i)
			break
		}
	}
	m.findingPane = 1
	m.findingDetailFocus = false
	m.findingDirectReturn = true
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
	m.findingSection = 0
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
		severity := strings.ToUpper(domain.EffectiveSeverity(*f))
		if severity == "UNKNOWN" || severity == "INFO" {
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
	lines := strings.Split(ansi.Wrap(body, max(1, width), ""), "\n")
	// Add our own color after stripping control sequences from target output.
	for i, line := range lines {
		if strings.HasPrefix(line, "Критичность: ") {
			lines[i] = rowStyle.Bold(true).Foreground(severityColor(domain.EffectiveSeverity(*f))).Render(line)
		}
	}
	return lines
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

func (m model) updateFindingDetails(key string) (tea.Model, tea.Cmd) {
	// Compatibility for screens opened by older modules; all navigation and
	// deletion now belong to the same result screen.
	if m.screen == "finding-details" {
		m.screen = "project-results"
		m.resultsScope = resultScope{host: m.currentHost()}
		m.projectResultsReturn = "desk"
	}
	return m.updateProjectResults(key)
}

func (m model) viewFindingDetails(w int) string { return m.viewProjectResults(w) }
