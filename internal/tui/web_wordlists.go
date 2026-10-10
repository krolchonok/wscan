package tui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type webWordlistChoice struct {
	name, path string
	size       int64
}

func secListsWebRoots(appDir string) []string {
	return []string{
		filepath.Join(appDir, "wordlists", "SecLists", "Discovery", "Web-Content"),
		"/usr/share/seclists/Discovery/Web-Content",
		"/usr/share/wordlists/SecLists/Discovery/Web-Content",
		"/usr/share/wordlists/seclists/Discovery/Web-Content",
	}
}
func defaultWebWordlist(appDir string) string {
	for _, root := range secListsWebRoots(appDir) {
		path := filepath.Join(root, "common.txt")
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
			return path
		}
	}
	return ""
}
func secListsWordlists(appDir string) []webWordlistChoice {
	choices := []webWordlistChoice{{name: "Встроенный короткий список"}}
	seen := map[string]bool{}
	priority := map[string]int{"common.txt": 0, "raft-small-directories.txt": 1, "raft-small-files.txt": 2, "directory-list-2.3-small.txt": 3, "raft-medium-directories.txt": 4, "raft-medium-files.txt": 5, "directory-list-2.3-medium.txt": 6}
	for _, root := range secListsWebRoots(appDir) {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".txt" && ext != ".lst" {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil || seen[rel] {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			seen[rel] = true
			choices = append(choices, webWordlistChoice{filepath.ToSlash(rel), path, info.Size()})
			return nil
		})
	}
	sort.SliceStable(choices[1:], func(i, j int) bool {
		a, b := choices[i+1], choices[j+1]
		pa, ok := priority[a.name]
		if !ok {
			pa = 100
		}
		pb, ok := priority[b.name]
		if !ok {
			pb = 100
		}
		if pa != pb {
			return pa < pb
		}
		return a.name < b.name
	})
	return choices
}
func (m model) openWebWordlists() (tea.Model, tea.Cmd) {
	b := &m.webDiscovery
	b.wordlists = secListsWordlists(m.appDir)
	b.wordlistFilter = ""
	b.wordlistIndex = 0
	for i, c := range b.wordlists {
		if c.path == b.options.Wordlist {
			b.wordlistIndex = i
			break
		}
	}
	m.screen = "web-wordlists"
	m.message = ""
	return m, nil
}
func (b webDiscoveryState) filteredWordlists() []webWordlistChoice {
	if b.wordlistFilter == "" {
		return b.wordlists
	}
	filtered := []webWordlistChoice{}
	for _, c := range b.wordlists {
		if strings.Contains(strings.ToLower(c.name), strings.ToLower(b.wordlistFilter)) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}
func (m model) updateWebWordlists(key string) (tea.Model, tea.Cmd) {
	b := &m.webDiscovery
	choices := b.filteredWordlists()
	switch key {
	case "esc", "q":
		m.screen = "web-discovery"
	case "up", "k":
		b.wordlistIndex = max(0, b.wordlistIndex-1)
	case "down", "j":
		b.wordlistIndex = min(max(0, len(choices)-1), b.wordlistIndex+1)
	case "pgup":
		b.wordlistIndex = max(0, b.wordlistIndex-10)
	case "pgdown":
		b.wordlistIndex = min(max(0, len(choices)-1), b.wordlistIndex+10)
	case "/":
		m.startInput("web-wordlist-filter")
		m.input = b.wordlistFilter
	case "p":
		m.startInput("web-discovery-wordlist")
		m.input = b.options.Wordlist
	case "enter":
		if len(choices) == 0 {
			m.message = "Нет словарей по фильтру"
			return m, nil
		}
		choice := choices[min(b.wordlistIndex, len(choices)-1)]
		b.options.Wordlist = choice.path
		m.screen = "web-discovery"
		m.message = "Словарь: " + choice.name
	}
	return m, nil
}
func (m model) viewWebWordlists(w int) string {
	b := m.webDiscovery
	choices := b.filteredWordlists()
	body := headingStyle.Render("Web — словари SecLists") + "\n↑/↓ выбрать · Enter применить · / поиск · p свой путь · Esc назад\n"
	if b.wordlistFilter != "" {
		body += "Фильтр: " + smbDisplayName(b.wordlistFilter) + "\n"
	}
	body += fmt.Sprintf("Доступно: %d · common / raft-small — быстрый старт\n", len(choices))
	lo, hi := windowRange(b.wordlistIndex, len(choices), max(1, m.panelRows()-6))
	for i := lo; i < hi; i++ {
		c := choices[i]
		label := c.name
		if c.path != "" {
			label += fmt.Sprintf(" · %.1f КБ", float64(c.size)/1024)
		}
		body += renderListRow(sanitizeWinRMText(label), i == b.wordlistIndex, w)
	}
	if len(b.wordlists) <= 1 {
		body += "\nSecLists не найден. p — указать путь к своему словарю."
	}
	return m.renderPanel(w, body)
}
