package main

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// This standalone mock has no storage, scanner, credentials or network clients.
type entry struct {
	title, subtitle string
	children        []entry
}
type demo struct {
	root          entry
	path          []int
	cursors       []int
	width, height int
	notice        string
}

func actions(names ...string) []entry {
	var rows []entry
	for _, name := range names {
		rows = append(rows, entry{title: name})
	}
	return rows
}
func fixtures() entry {
	return entry{title: "Проект: Заказчик · демо", children: []entry{
		{title: "192.0.2.0/24", subtitle: "Основная сеть · 3 машины", children: []entry{
			{title: "192.0.2.10 · DC01", subtitle: "Windows Server 2022 · контроллер домена · demo.test", children: []entry{
				{title: "389/tcp · LDAP", children: actions("Сведения о домене", "Разведка без учётки", "Разведка с учёткой", "Сбор BloodHound")},
				{title: "445/tcp · SMB", children: actions("Проверить сервис", "Выбрать учётку", "Открыть общие папки")},
				{title: "88/tcp · Kerberos", children: actions("Сведения о сервисе", "Выбрать проверки")},
			}},
			{title: "192.0.2.20 · APP01", subtitle: "Windows Server 2019 · сервер приложений", children: []entry{
				{title: "443/tcp · HTTPS", children: actions("Открыть сведения", "Выбрать проверки", "Поиск каталогов")},
				{title: "5985/tcp · WinRM", children: actions("Выбрать учётку", "Подключиться", "Открыть проводник", "Открыть консоль")},
				{title: "1433/tcp · MSSQL", children: actions("Выбрать учётку", "Подключиться", "Просмотреть базы", "Открыть SQL-консоль")},
			}},
			{title: "192.0.2.30 · WS01", subtitle: "Windows 11 · рабочая станция", children: []entry{
				{title: "445/tcp · SMB", children: actions("Проверить сервис", "Выбрать учётку", "Открыть общие папки")},
				{title: "3389/tcp · RDP", children: actions("Сведения о сервисе", "Выбрать проверки")},
			}},
		}},
		{title: "198.51.100.0/24", subtitle: "Серверная сеть · 1 машина", children: []entry{
			{title: "198.51.100.10 · WEB01", subtitle: "Ubuntu 24.04 · веб-сервер", children: []entry{
				{title: "22/tcp · SSH", children: actions("Сведения о сервисе", "Выбрать учётку", "Подключиться")},
				{title: "443/tcp · HTTPS", children: actions("Выбрать проверки", "Поиск каталогов")},
			}},
		}},
	}}
}
func (m demo) Init() tea.Cmd { return nil }
func (m demo) current() entry {
	node := m.root
	for _, index := range m.path {
		node = node.children[index]
	}
	return node
}
func (m *demo) back() {
	if len(m.path) > 0 {
		m.path = m.path[:len(m.path)-1]
		m.cursors = m.cursors[:len(m.cursors)-1]
	}
	m.notice = ""
}
func (m *demo) open() {
	index := m.cursors[len(m.cursors)-1]
	node := m.current()
	if index >= len(node.children) {
		m.notice = ""
		return
	}
	selected := node.children[index]
	if len(selected.children) == 0 {
		m.notice = "Демо: «" + selected.title + "». Ничего не выполняется."
		return
	}
	m.path = append(m.path, index)
	m.cursors = append(m.cursors, 0)
	m.notice = ""
}
func (m demo) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch x := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = x.Width, x.Height
	case tea.KeyMsg:
		pos := len(m.cursors) - 1
		switch x.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up":
			m.cursors[pos] = max(0, m.cursors[pos]-1)
			m.notice = ""
		case "down":
			m.cursors[pos] = min(len(m.current().children), m.cursors[pos]+1)
			m.notice = ""
		case "left", "esc":
			m.back()
		case "right", "enter":
			if m.cursors[pos] == len(m.current().children) {
				if len(m.path) == 0 {
					return m, tea.Quit
				}
				m.back()
			} else {
				m.open()
			}
		}
	}
	return m, nil
}
func fit(s string, width int) string { return ansi.Truncate(s, max(1, width), "…") }
func (m demo) View() string {
	width, height := max(30, m.width), max(10, m.height)
	accent := lipgloss.NewStyle().Foreground(lipgloss.Color("#67E8C5")).Bold(true)
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("#82949A"))
	levels := []string{"Сети", "Машины", "Сервисы", "Действия"}
	var crumbs []string
	node := m.root
	crumbs = append(crumbs, "Проект")
	for _, index := range m.path {
		node = node.children[index]
		crumbs = append(crumbs, node.title)
	}
	header := accent.Render("WSCAN · МАКЕТ") + muted.Render("   Вымышленные данные")
	var body strings.Builder
	body.WriteString(accent.Render(levels[len(m.path)]) + "\n")
	body.WriteString(fit(node.title, width-6) + "\n")
	if node.subtitle != "" {
		body.WriteString(muted.Render(fit(node.subtitle, width-6)) + "\n")
	}
	rows := append([]entry(nil), node.children...)
	last := entry{title: "← Назад"}
	if len(m.path) == 0 {
		last = entry{title: "Закрыть демо"}
	}
	rows = append(rows, last)
	selected := m.cursors[len(m.cursors)-1]
	visible := max(1, (height-10)/2)
	if len(m.path) >= 2 {
		visible = max(1, height-9)
	}
	lo := max(0, selected-visible/2)
	lo = min(lo, max(0, len(rows)-visible))
	hi := min(len(rows), lo+visible)
	for i := lo; i < hi; i++ {
		marker := "  "
		if i == selected {
			marker = "▶ "
		}
		title := fit(marker+rows[i].title, width-6)
		if i == selected {
			title = accent.Render(title)
		}
		body.WriteString(title + "\n")
		if rows[i].subtitle != "" && len(m.path) < 2 {
			body.WriteString(muted.Render(fit("  "+rows[i].subtitle, width-6)) + "\n")
		}
	}
	panel := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#29434A")).Padding(0, 1).Width(width - 2).Height(height - 6).MaxHeight(height - 4).Render(body.String())
	notice := m.notice
	if notice == "" {
		notice = "Только навигация. Сканирования и подключения отключены."
	}
	return strings.Join([]string{fit(header, width), muted.Render(fit(strings.Join(crumbs, " → "), width)), panel, fit(notice, width), muted.Render(fit("↑↓ выбор · → / Enter открыть · ← назад", width))}, "\n")
}
func main() {
	m := demo{root: fixtures(), cursors: []int{0}, width: 100, height: 30}
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
