package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Dimensions are the complete pane rectangles, including borders and padding.
type hostPaneLayout struct {
	mode                     string
	hosts, ports, details    int
	portHeight, detailHeight int
}

func hostLayout(width, height int) hostPaneLayout {
	if width >= 128 && height >= 14 {
		// Keep addresses and DNS names readable while allowing service names
		// to use the extra room in a wide terminal.
		hosts := min(72, max(40, width*28/100))
		ports := min(72, max(36, width*27/100))
		return hostPaneLayout{mode: "columns", hosts: hosts, ports: ports, details: width - hosts - ports}
	}
	if width >= 88 && height >= 14 {
		upper := height / 2
		hosts := min(44, max(36, width/3))
		return hostPaneLayout{mode: "stack", hosts: hosts, ports: width - hosts, details: width - hosts, portHeight: upper, detailHeight: height - upper}
	}
	return hostPaneLayout{mode: "single", hosts: width, ports: width, details: width}
}

func renderColumn(body string, width, height int, focused bool) string {
	return colBoxStyle(width, height, focused).Render(fitContent(wrapPaneBody(body, width), width, height))
}

// Keep the selected item visible when some entries occupy two terminal rows.
func variableRowRange(pivot int, heights []int, visible int) (int, int) {
	if len(heights) == 0 {
		return 0, 0
	}
	visible = max(1, visible)
	pivot = min(max(0, pivot), len(heights)-1)
	lo, hi, used := pivot, pivot+1, heights[pivot]
	for lo > 0 && used+heights[lo-1] <= max(heights[pivot], visible/2) {
		lo--
		used += heights[lo]
	}
	for hi < len(heights) && used+heights[hi] <= visible {
		used += heights[hi]
		hi++
	}
	for lo > 0 && used+heights[lo-1] <= visible {
		lo--
		used += heights[lo]
	}
	return lo, hi
}

func wrapPaneBody(body string, width int) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if ansi.StringWidth(line) > max(1, width) {
			lines[i] = ansi.Wrap(line, max(1, width), "")
		}
	}
	return strings.Join(lines, "\n")
}

func dialogWidth(screen string, width int) int {
	limit := 96
	switch screen {
	case "input", "delete-confirm", "repair-target":
		limit = 72
	case "action-menu":
		limit = 88
	}
	return min(width, limit)
}

func (m model) viewHostWorkspace(width int) string {
	height := m.bodyHeight()
	layout := hostLayout(width, height)
	if len(m.hostOrder) == 0 {
		var body strings.Builder
		body.WriteString(headingStyle.Render("Хосты") + "\n\n")
		if m.hostNetwork != "" {
			body.WriteString("Подсеть: " + m.hostNetwork + "\n\n")
			body.WriteString("Хосты в этой подсети пока не найдены.\n1 — открыть подсети и запустить обнаружение.\n2 — показать все хосты проекта.")
		} else {
			body.WriteString("Добавь отдельный хост клавишей a\nили открой подсети клавишей 1 и найди машины в диапазоне.")
		}
		return m.renderPanel(width, body.String())
	}
	switch layout.mode {
	case "columns":
		return lipgloss.JoinHorizontal(lipgloss.Top,
			m.renderHostsColumn(layout.hosts-4, height-2),
			m.renderServicesColumn(layout.ports-4, height-2),
			m.renderDetailsColumn(layout.details-4, height-2))
	case "stack":
		right := lipgloss.JoinVertical(lipgloss.Left,
			m.renderServicesColumn(layout.ports-4, layout.portHeight-2),
			m.renderDetailsColumn(layout.details-4, layout.detailHeight-2))
		return lipgloss.JoinHorizontal(lipgloss.Top, m.renderHostsColumn(layout.hosts-4, height-2), right)
	default:
		switch m.focusCol {
		case 1:
			return m.renderServicesColumn(width-4, height-2)
		case 2:
			return m.renderDetailsColumn(width-4, height-2)
		default:
			return m.renderHostsColumn(width-4, height-2)
		}
	}
}

func (m model) currentNetwork() string {
	networks := m.networkTargets()
	if m.networkIndex >= 0 && m.networkIndex < len(networks) {
		return networks[m.networkIndex]
	}
	return ""
}

func (m model) networkJob(cidr string) *job {
	var latest *job
	for _, candidate := range m.jobs {
		if candidate.projectID != m.current.ID {
			continue
		}
		for _, target := range candidate.targets {
			if target == cidr && (latest == nil || candidate.id > latest.id) {
				latest = candidate
			}
		}
	}
	return latest
}

func (m model) viewNetworkWorkspace(width int) string {
	height := m.bodyHeight()
	networks := m.networkTargets()
	if len(networks) == 0 {
		return m.renderPanel(width, headingStyle.Render("Подсети")+"\n\nДобавь диапазон клавишей a.\nНапример: 10.0.0.0/24\n\nПосле обнаружения машины появятся в отдельном окне «Хосты».")
	}
	listWidth := width
	split := width >= 100 && height >= 12
	if split {
		listWidth = min(58, max(40, width*45/100))
	}
	contentWidth := max(1, listWidth-4)
	contentHeight := max(1, height-2)
	var list strings.Builder
	list.WriteString(headingStyle.Render(fmt.Sprintf("ПОДСЕТИ · %d", len(networks))) + "\n")
	list.WriteString(mutedStyle.Render("Диапазон                 Хосты") + "\n")
	reserve := 4
	if !split {
		reserve += 3
	}
	lo, hi := windowRange(m.networkIndex, len(networks), max(1, contentHeight-reserve))
	list.WriteString(moreLine(lo, true))
	for i := lo; i < hi; i++ {
		cidr := networks[i]
		mark := "[ ]"
		if m.selectedNetworks[cidr] {
			mark = "[x]"
		}
		count := fmt.Sprintf("%d", m.networkHostCount(cidr))
		labelWidth := max(1, contentWidth-len(count)-9)
		label := ansi.Truncate(cidr, labelWidth, "…")
		line := mark + " " + label + strings.Repeat(" ", max(1, labelWidth-ansi.StringWidth(label)+1)) + count
		list.WriteString(renderListRow(line, i == m.networkIndex, contentWidth+4))
	}
	list.WriteString(moreLine(len(networks)-hi, false))
	if !split {
		list.WriteString("\n" + ansi.Truncate(m.currentNetwork(), contentWidth, "…") + "\n")
		list.WriteString(mutedStyle.Render("o — хосты этой подсети · Enter — действия"))
	}
	left := renderColumn(list.String(), contentWidth, contentHeight, true)
	if !split {
		return left
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, left,
		renderColumn(m.networkCard(width-listWidth-4), width-listWidth-4, contentHeight, false))
}

func (m model) networkCard(width int) string {
	cidr := m.currentNetwork()
	hosts := m.networkHosts(cidr)
	ports, findings := 0, 0
	for _, host := range hosts {
		p, f := m.hostSummary(host)
		ports += p
		findings += f
	}
	var body strings.Builder
	body.WriteString(headingStyle.Render("ВЫБРАННАЯ ПОДСЕТЬ") + "\n\n")
	body.WriteString(cidr + "\n\n")
	fmt.Fprintf(&body, "Хостов в проекте: %d\nОткрытых портов: %d\nРезультатов проверок: %d\n", len(hosts), ports, findings)
	if recent := m.networkJob(cidr); recent != nil {
		body.WriteString("\nПоследняя задача\n")
		body.WriteString(ansi.Truncate(statusIcon(recent.status)+" "+recent.stage, width, "…") + "\n")
	}
	body.WriteString("\nEnter  Обнаружение и сканирование\no      Открыть хосты этой подсети\nSpace  Отметить диапазон\n\n2      Все хосты проекта")
	return body.String()
}

func (m model) navigationLine() string {
	if m.current.ID == 0 || m.screen == "projects" {
		return mutedStyle.Render("Проекты · Enter открыть · n создать")
	}
	if m.screen != "desk" && m.screen != "networks" && m.screen != "jobs" && m.screen != "interaction-menu" {
		label := map[string]string{
			"interaction-menu": "Взаимодействие", "smb-browser": "SMB-проводник",
			"action-menu": "Действия", "disc-options": "Параметры сканирования",
			"input": "Добавление / изменение", "delete-confirm": "Удаление",
			"catalog": "Проверки", "catalog-groups": "Библиотека проверок",
			"settings": "Настройки проекта", "credentials": "Учётные записи",
			"history": "История запусков", "finding-details": "Результат проверки",
			"job-details": "Подробности задачи", "help": "Клавиши",
		}[m.screen]
		if label == "" {
			label = "Параметры действия"
		}
		return headingStyle.Render(label) + mutedStyle.Render(" · Esc назад")
	}
	items := []struct{ label, screen string }{{"1 Подсети", "networks"}, {"2 Хосты", "desk"}, {"3 Задачи", "jobs"}, {"4 Взаимодействие", "interaction-menu"}}
	var parts []string
	for _, item := range items {
		if m.screen == item.screen {
			parts = append(parts, headingStyle.Render("["+item.label+"]"))
		} else {
			parts = append(parts, mutedStyle.Render(item.label))
		}
	}
	if m.width >= 100 && m.screen == "desk" {
		parts = append(parts, mutedStyle.Render("i Взаимодействие · t Проверки · c Учётки · p Настройки"))
	}
	return strings.Join(parts, "  ")
}

func (m model) contextLine() string {
	switch m.screen {
	case "networks":
		return mutedStyle.Render(fmt.Sprintf("Подсети проекта: %d · отмечено: %d", len(m.networkTargets()), len(m.selectedNetworks)))
	case "desk":
		scope := "Все хосты проекта"
		if m.hostNetwork != "" {
			scope = m.hostNetwork + " · 2 показать все"
		}
		panes := []string{"Хосты", "Порты", "Результаты"}
		active := panes[min(2, max(0, m.focusCol))]
		if m.width > 0 && m.width < 88 {
			return headingStyle.Render(active) + mutedStyle.Render(fmt.Sprintf(" · %s · %d хостов", scope, len(m.hostOrder)))
		}
		return mutedStyle.Render(fmt.Sprintf("%s · %d хостов · выбрано %d · ", scope, len(m.hostOrder), len(m.selectedTargetHosts()))) + headingStyle.Render(active)
	default:
		return ""
	}
}
