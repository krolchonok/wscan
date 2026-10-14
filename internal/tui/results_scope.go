package tui

import (
	"fmt"
	"sort"
	"wscan/internal/domain"
)

// resultScope is captured when a result screen opens. Moving the desk cursor
// or completing another job must not silently change what the screen contains.
type resultScope struct {
	host     string
	service  *domain.Service
	runID    int64
	port     int
	protocol string
}

func (m model) rawProjectFindings() []domain.Finding {
	var out []domain.Finding
	hosts := make([]string, 0, len(m.inventory))
	for host := range m.inventory {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		out = append(out, m.inventory[host].findings...)
	}
	return orderedResults(out)
}
func (m model) resultsRawFindings() []domain.Finding {
	scope := m.resultsScope
	if scope.runID != 0 {
		for _, run := range m.history {
			if run.ID == scope.runID {
				return run.Findings
			}
		}
		for _, j := range m.jobs {
			if j.projectID == m.current.ID && j.runID == scope.runID && j.result != nil {
				return j.result.Findings
			}
		}
		return nil
	}
	if scope.port > 0 {
		return m.portScopedFindings(scope)
	}
	if scope.host != "" {
		if scope.service != nil {
			return m.rawFindingsForService(scope.host, *scope.service)
		}
		if h := m.inventory[scope.host]; h != nil {
			return h.findings
		}
		return nil
	}
	return m.rawProjectFindings()
}
func (m model) scopedResults() []domain.Finding {
	return groupedProjectResults(orderedResults(m.resultsRawFindings()))
}
func (m model) resultsScopeLabel() string {
	if m.resultsScope.runID != 0 {
		return fmt.Sprintf("Запуск #%d", m.resultsScope.runID)
	}
	if m.resultsScope.port > 0 {
		label := fmt.Sprintf("Порт %d/%s", m.resultsScope.port, m.resultsScope.protocol)
		if m.resultsScope.host != "" {
			label += " · хост " + m.resultsScope.host
		} else {
			label += " · весь проект"
		}
		return label
	}
	if s := m.resultsScope.service; s != nil {
		return fmt.Sprintf("%s · %d/%s", m.resultsScope.host, s.Port, s.Protocol)
	}
	if m.resultsScope.host != "" {
		return "Хост " + m.resultsScope.host
	}
	return "Весь проект"
}
func (m *model) openScopedResults(scope resultScope) {
	previous := m.screen
	m.openProjectResults()
	m.projectResultsReturn = previous
	m.resultsScope = scope
	m.projectResultsSearch = ""
	m.projectResultsFilter = "important"
	m.refreshProjectResultSelection()
}
func (m *model) openRunResults(runID int64) {
	m.openScopedResults(resultScope{runID: runID})
	// A finished informational scan must be visible when opened explicitly.
	if len(m.filteredProjectFindings()) == 0 && len(m.scopedResults()) > 0 {
		m.projectResultsFilter = "all"
		m.refreshProjectResultSelection()
	}
}
