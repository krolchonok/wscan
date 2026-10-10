package tui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
)

func (m model) projectHasActiveJobs(id int64) bool {
	for _, j := range m.jobs {
		if j.projectID == id && j.active() {
			return true
		}
	}
	return false
}

func (m *model) requestProjectDelete() {
	if m.selected < 0 || m.selected >= len(m.projects) {
		return
	}
	p := m.projects[m.selected]
	if m.projectHasActiveJobs(p.ID) {
		m.message = "В проекте есть активные задачи. Останови их в «Задачах» (g) и дождись завершения."
		return
	}
	m.deleteProjectID = p.ID
	m.screen = "project-delete-confirm"
}

func (m model) viewProjectDelete(width int) string {
	p := m.findProject(m.deleteProjectID)
	return m.renderPanel(width, headingStyle.Render("Удалить проект?")+fmt.Sprintf("\n\n%s\n\nБудут удалены цели, выбранные проверки, история запусков,\nпорты, находки и учётные записи этого проекта.\nУдаление нельзя отменить.\n\nEnter — удалить · Esc — отмена", p.Name))
}

func (m model) updateProjectDelete(key string) (tea.Model, tea.Cmd) {
	if key == "esc" || key == "n" {
		m.screen, m.deleteProjectID = "projects", 0
		return m, nil
	}
	if key != "enter" && key != "y" {
		return m, nil
	}
	id := m.deleteProjectID
	if id == 0 {
		m.screen = "projects"
		return m, nil
	}
	if m.projectHasActiveJobs(id) {
		m.screen = "projects"
		m.message = "Проект не удалён: есть активные задачи."
		return m, nil
	}
	name := m.findProject(id).Name
	if err := m.store.DeleteProject(m.ctx, id); err != nil {
		m.message = err.Error()
		return m, nil
	}
	var kept []*job
	for _, j := range m.jobs {
		if j.projectID != id {
			kept = append(kept, j)
		}
	}
	m.jobs = kept
	if m.current.ID == id {
		m.current = m.findProject(0)
		m.inventory, m.selectedHosts = nil, nil
		m.hostOrder, m.history = nil, nil
		m.selectedNetworks = nil
		m.hostNetwork = ""
	}
	m.screen, m.deleteProjectID = "projects", 0
	if err := m.reload(); err != nil {
		m.message = err.Error()
		return m, nil
	}
	m.selected = min(m.selected, max(0, len(m.projects)-1))
	m.message = "Проект удалён: " + name
	return m, nil
}
