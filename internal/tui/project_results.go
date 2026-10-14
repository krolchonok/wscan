package tui

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/domain"
)

// projectFindings deliberately ignores the selected host and network scope.
func (m model) projectFindings() []domain.Finding {
	return groupedProjectResults(m.rawProjectFindings())
}
func (m model) filteredProjectFindings() []domain.Finding {
	query := strings.ToLower(strings.TrimSpace(m.projectResultsSearch))
	var out []domain.Finding
	for _, f := range m.scopedResults() {
		filter := m.projectResultsFilter
		if filter == "important" && resultClass(f) == "Сведения" && f.TemplateID != "ui/coercion-summary" && !(strings.HasPrefix(f.TemplateID, "adscan-") || strings.HasPrefix(f.TemplateID, "ad-access/bloodhound-ce")) {
			continue
		}
		if filter == "risk" && resultClass(f) != "Риск" {
			continue
		}
		if filter == "error" && resultClass(f) != "Ошибка" {
			continue
		}
		if filter != "" && filter != "all" && filter != "risk" && filter != "error" && filter != "important" && domain.EffectiveSeverity(f) != filter {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(f.Target+" "+f.MatchedAt+" "+f.TemplateID+" "+resultTitle(f)+" "+f.Description+" "+f.Evidence+" "+resultSearchDetails(f)), query) {
			continue
		}
		out = append(out, f)
	}
	return out
}
func projectResultLabel(f domain.Finding) string {
	return projectResultLocation(f) + " · " + resultLabel(f)
}

func projectResultLocation(f domain.Finding) string {
	if host, port, _, ok := findingEndpoint(f.MatchedAt); ok {
		if port > 0 {
			return net.JoinHostPort(host, strconv.Itoa(port))
		}
		return host
	}
	// AD reports store the full scan scope in Target and the actual host in
	// MatchedAt. Older saved runs use the same format.
	if address := strings.TrimSpace(f.MatchedAt); len(strings.Fields(address)) == 1 {
		return address
	}
	if len(strings.Fields(f.Target)) > 1 {
		return "Область: " + scanScopeLabel(f.Target)
	}
	return f.Target
}
func (m *model) openProjectResults() {
	if m.screen != "project-results" && m.screen != "finding-details" {
		m.projectResultsReturn = m.screen
	}
	m.findingDirectReturn = false
	m.findingDetailFocus = false
	m.screen = "project-results"
	m.resultsScope = resultScope{}
	m.findingIndex = 0
	m.projectResultsSelected = nil
	if m.projectResultsFilter == "" {
		m.projectResultsFilter = "important"
	}
	m.resultDeleteConfirm = false
	m.findingRaw = false
	m.findingPane = 0
	m.findingOffset = 0
	m.refreshProjectResultSelection()
	m.message = ""
}
func (m *model) refreshProjectResultSelection() {
	if !m.selectFinding(m.findingIndex) {
		m.findingDetail = nil
		m.findingIndex = 0
		m.findingOffset = 0
	}
}
func (m model) updateProjectResults(key string) (tea.Model, tea.Cmd) {
	if m.resultDeleteConfirm {
		return m.confirmResultDelete(key)
	}
	switch key {
	case "m":
		if len(m.findingSections()) > 3 {
			m.findingPane, m.findingSection = 1, 3
			m.findingRaw, m.findingDetailFocus = false, true
			m.findingOffset = 0
		}
		return m, nil
	case "y":
		if m.findingPane == 1 && m.findingSection == 3 && !m.findingRaw {
			return m.copyFindingCommand()
		}
		return m, nil
	case "pgup", "pgdown":
		if m.findingPane == 0 {
			step := m.resultListRows(m.width)
			if key == "pgup" {
				step = -step
			}
			m.selectFinding(m.findingIndex + step)
			return m, nil
		}
	case "delete", "backspace", "d":
		return m.requestResultDelete(false)
	case "D":
		return m.requestResultDelete(true)
	case " ":
		if m.findingDetail != nil {
			if m.projectResultsSelected == nil {
				m.projectResultsSelected = map[string]bool{}
			}
			k := resultSelectionKey(*m.findingDetail)
			if m.projectResultsSelected[k] {
				delete(m.projectResultsSelected, k)
			} else {
				m.projectResultsSelected[k] = true
			}
		}
		return m, nil
	case "a":
		rows := m.filteredProjectFindings()
		all := len(rows) > 0
		for _, f := range rows {
			if !m.projectResultsSelected[resultSelectionKey(f)] {
				all = false
			}
		}
		if m.projectResultsSelected == nil {
			m.projectResultsSelected = map[string]bool{}
		}
		for _, f := range rows {
			if all {
				delete(m.projectResultsSelected, resultSelectionKey(f))
			} else {
				m.projectResultsSelected[resultSelectionKey(f)] = true
			}
		}
		return m, nil
	case "esc", "q":
		if m.findingPane == 1 {
			m.findingPane = 0
			m.findingRaw = false
			if m.findingDirectReturn {
				m.screen = m.projectResultsReturn
				m.findingDirectReturn = false
			}
			return m, nil
		}
	case "v":
		m.serviceInventoryProject = true
		m.serviceInventoryFilter = ""
		m.serviceInventoryIndex = 0
		m.serviceInventoryEditing = false
		m.serviceInventorySelected = nil
		m.screen = "service-inventory"
		return m, nil
	case "p":
		m.openPortBrowser()
		return m, nil
	case "/":
		m.startInput("project-results-search")
		m.input = m.projectResultsSearch
		return m, nil
	case "i":
		m.projectResultsFilter = "all"
		m.findingPane = 0
		m.projectResultsSelected = nil
		m.findingIndex = 0
		m.refreshProjectResultSelection()
		return m, nil
	case "f":
		filters := []string{"important", "risk", "info", "error", "all", "critical", "high", "medium", "low"}
		index := 0
		for i, filter := range filters {
			if filter == m.projectResultsFilter {
				index = i
				break
			}
		}
		m.projectResultsFilter = filters[(index+1)%len(filters)]
		m.findingPane = 0
		m.projectResultsSelected = nil
		m.findingIndex = 0
		m.refreshProjectResultSelection()
		return m, nil
	case "c":
		m.projectResultsSelected = nil
		m.findingPane = 0
		m.projectResultsSearch = ""
		m.projectResultsFilter = "important"
		m.findingIndex = 0
		m.refreshProjectResultSelection()
		return m, nil
	}
	if m.findingPane == 1 {
		if m.splitResultDetails(m.width) {
			switch key {
			case "left":
				m.findingDetailFocus = false
				return m, nil
			case "right", "enter":
				m.findingDetailFocus = true
				return m, nil
			}
			if !m.findingDetailFocus {
				index := m.findingIndex
				handled := true
				switch key {
				case "up", "k":
					index--
				case "down", "j":
					index++
				case "home":
					index = 0
				case "end":
					index = len(m.filteredProjectFindings()) - 1
				case "pgup":
					index -= max(1, m.bodyHeight()-7)
				case "pgdown":
					index += max(1, m.bodyHeight()-7)
				default:
					handled = false
				}
				if handled {
					section := m.findingSection
					m.selectFinding(index)
					m.findingSection = min(section, len(m.findingSections())-1)
					return m, nil
				}
			}
		}
		rows := m.resultDetailRows(m.width)
		last := max(0, len(m.projectResultDetailLines(max(1, m.resultDetailWidth(m.width)-6)))-rows)
		switch key {
		case "up", "k":
			m.findingOffset = max(0, m.findingOffset-1)
		case "down", "j":
			m.findingOffset = min(last, m.findingOffset+1)
		case "pgup":
			m.findingOffset = max(0, m.findingOffset-rows)
		case "pgdown":
			m.findingOffset = min(last, m.findingOffset+rows)
		case "home":
			m.findingOffset = 0
		case "end":
			m.findingOffset = last
		case "tab", "shift+tab":
			sections := len(m.findingSections())
			step := 1
			if key == "shift+tab" {
				step = sections - 1
			}
			m.findingSection = (m.findingSection + step) % sections
			m.findingRaw = false
			m.findingOffset = 0
		case "[", "]":
			step := 1
			if key == "[" {
				step = -1
			}
			m.selectFinding(m.findingIndex + step)
		case "left":
			return m.updateProjectResults("esc")
		case "r":
			m.findingRaw = !m.findingRaw
			m.findingOffset = 0
		}
		return m, nil
	}
	switch key {
	case "enter", "right":
		if m.findingDetail != nil {
			m.findingPane = 1
			m.findingDetailFocus = false
			m.findingDirectReturn = false
			m.findingRaw = false
			m.findingOffset = 0
		}
	case "r":
		if m.findingDetail != nil {
			m.findingPane = 1
			m.findingDetailFocus = false
			m.findingDirectReturn = false
			m.findingRaw = true
			m.findingOffset = 0
		}
	case "up", "k":
		m.selectFinding(m.findingIndex - 1)
	case "down", "j":
		m.selectFinding(m.findingIndex + 1)
	case "home":
		m.selectFinding(0)
	case "end":
		m.selectFinding(len(m.filteredProjectFindings()) - 1)
	case "esc", "q":
		m.screen = m.projectResultsReturn
		if m.screen == "" || m.screen == "project-results" {
			m.screen = "desk"
		}
	}
	return m, nil
}
func (m model) projectResultsSummary() string {
	filter := m.projectResultsFilter
	if filter == "" || filter == "all" {
		filter = "все"
	}
	labels := map[string]string{"important": "основное", "risk": "риски", "error": "ошибки", "info": "сведения", "critical": "критические", "high": "высокие", "medium": "средние", "low": "низкие"}
	if label := labels[filter]; label != "" {
		filter = label
	}
	summary := fmt.Sprintf("%s · %s · фильтр: %s · выбрано: %d", m.current.Name+" · "+m.resultsScopeLabel(), resultCounts(m.scopedResults()), filter, len(m.projectResultsSelected))
	if m.projectResultsSearch != "" {
		summary += " · поиск: " + m.projectResultsSearch
	}
	return summary
}

func resultSearchDetails(f domain.Finding) string {
	if f.TemplateID == "ui/coercion-summary" {
		return f.Response
	}
	return ""
}
