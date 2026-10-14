package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func TestReconFilterOpensSelectedMachine(t *testing.T) {
	m := workspaceFixture()
	m.screen = "recon"
	m.reconFilter = 1
	hosts := m.reconHosts()
	if len(hosts) != 3 {
		t.Fatalf("AD/Windows hosts: %v", hosts)
	}
	m.reconIndex = 2
	selected := hosts[2]
	next, _ := m.updateRecon("enter")
	m = next.(model)
	if m.screen != "recon" || !m.reconCardFocus || m.selectedReconHost() != selected {
		t.Fatalf("wrong host opened: %s %s", m.screen, m.currentHost())
	}
	next, _ = m.updateRecon("enter")
	m = next.(model)
	if m.screen != "desk" || m.focusCol != 1 {
		t.Fatal("services menu did not open")
	}
	next, _ = m.updateDesk("esc")
	if next.(model).screen != "recon" {
		t.Fatal("Esc did not return to recon")
	}
}

func TestReconSelectedRowSurvivesResize(t *testing.T) {
	m := workspaceFixture()
	m.screen = "recon"
	m.reconIndex = len(m.reconHosts()) - 1
	host := m.reconHosts()[m.reconIndex]
	for _, size := range [][2]int{{55, 18}, {100, 24}, {160, 40}} {
		m.width, m.height = size[0], size[1]
		view := ansi.Strip(m.View())
		if !strings.Contains(view, host) || !strings.Contains(view, "▶") {
			t.Fatalf("selected host invisible at %v:\n%s", size, view)
		}
	}
}

func TestReconADShortcutRequiresExplicitLaunch(t *testing.T) {
	m := workspaceFixture()
	m.screen = "recon"
	m.reconMenuFocus = true
	m.reconMenuIndex = 1
	next, cmd := m.updateRecon("enter")
	m = next.(model)
	if cmd != nil || m.screen != "ad-menu" || len(m.jobs) != 0 {
		t.Fatal("AD shortcut should open setup without running a scan")
	}
}

func TestReconMenuKeyboardFlow(t *testing.T) {
	m := workspaceFixture()
	m.screen = "recon"
	next, _ := m.updateRecon("left")
	m = next.(model)
	if !m.reconMenuFocus {
		t.Fatal("Tab did not focus menu")
	}
	for i := 0; i < 8; i++ {
		next, _ = m.updateRecon("down")
		m = next.(model)
	}
	next, _ = m.updateRecon("enter")
	m = next.(model)
	if m.reconFilter != 1 || m.reconMenuFocus {
		t.Fatal("filter menu failed")
	}
	next, _ = m.updateRecon("c")
	if next.(model).screen != "recon" {
		t.Fatal("letter shortcut still opens credentials")
	}
}

func TestSidebarReturnsFromActionToMainHostsWithoutEscape(t *testing.T) {
	m := workspaceFixture()
	m.sidebarEnabled = true
	m.focusCol = 0
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if m.screen != "action-menu" {
		t.Fatal("host action menu did not open")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	m = next.(model)
	if m.screen != "desk" || m.focusCol != 0 {
		t.Fatal("Back did not return to main hosts")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'0'}})
	if next.(model).screen != "projects" {
		t.Fatal("Projects did not exit main hosts")
	}
}

func TestMainHostsArrowAndTabNavigation(t *testing.T) {
	for _, keys := range [][]tea.KeyType{
		{tea.KeyRight, tea.KeyRight, tea.KeyLeft, tea.KeyLeft, tea.KeyLeft, tea.KeyRight},
		{tea.KeyTab, tea.KeyTab, tea.KeyTab, tea.KeyTab, tea.KeyShiftTab, tea.KeyShiftTab},
	} {
		m := workspaceFixture()
		m.sidebarEnabled = true
		for i, key := range keys {
			next, _ := m.Update(tea.KeyMsg{Type: key})
			m = next.(model)
			col, menu := 0, false
			if keys[0] == tea.KeyRight {
				col = []int{1, 2, 1, 0, 0, 0}[i]
				menu = i == 4
			} else {
				col = []int{1, 2, 2, 0, 0, 2}[i]
				menu = i == 2 || i == 4
			}
			if m.screen != "desk" || m.focusCol != col || m.reconMenuFocus != menu {
				t.Fatalf("step %d: screen=%s column=%d menu=%v", i, m.screen, m.focusCol, m.reconMenuFocus)
			}
		}
	}
}

func TestSidebarScreensFitWithMenuVisible(t *testing.T) {
	for _, screen := range []string{"recon", "recon-host-menu", "desk", "jobs", "guided-scan", "project-results"} {
		for _, size := range [][2]int{{55, 18}, {100, 24}, {160, 40}} {
			m := workspaceFixture()
			m.screen = screen
			m.sidebarEnabled = true
			m.width, m.height = size[0], size[1]
			frame := m.View()
			if len(strings.Split(frame, "\n")) != m.height {
				t.Fatalf("%s: height", screen)
			}
			for _, line := range strings.Split(frame, "\n") {
				if ansi.StringWidth(line) != m.width {
					t.Fatalf("%s: width", screen)
				}
			}
			if !strings.Contains(ansi.Strip(frame), "← Назад") || !strings.Contains(ansi.Strip(frame), "Машины") {
				if screen != "recon" && screen != "recon-host-menu" && screen != "desk" {
					t.Fatalf("sidebar missing on %s", screen)
				}
			}
		}
	}
}

func TestSidebarLeftRightChangeFocus(t *testing.T) {
	m := workspaceFixture()
	m.sidebarEnabled = true
	m.screen = "recon"
	for _, screen := range []string{"recon", "recon-host-menu", "desk", "jobs", "guided-scan"} {
		m.screen = screen
		m.reconMenuFocus = false
		m.reconMenuIndex = 4
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyLeft})
		m = next.(model)
		if !m.reconMenuFocus || m.reconMenuIndex != 4 || m.screen != screen {
			t.Fatalf("left did not focus sidebar on %s", screen)
		}
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRight})
		m = next.(model)
		if m.reconMenuFocus || m.reconMenuIndex != 4 || m.screen != screen {
			t.Fatalf("right did not focus content on %s", screen)
		}
	}
}

func TestReconCardTracksHostAndArrows(t *testing.T) {
	m := workspaceFixture()
	m.screen = "recon"
	m.width, m.height = 160, 30
	first := m.selectedReconHost()
	next, _ := m.updateRecon("down")
	m = next.(model)
	second := m.selectedReconHost()
	if second == first || !strings.Contains(ansi.Strip(m.reconCard(60)), second) {
		t.Fatal("card did not follow selection")
	}
	next, _ = m.updateRecon("right")
	m = next.(model)
	if !m.reconCardFocus || m.screen != "recon" {
		t.Fatal("right did not focus card inline")
	}
	next, _ = m.updateRecon("down")
	m = next.(model)
	if m.selectedReconHost() != second || m.reconHostAction != 1 {
		t.Fatal("action movement changed host")
	}
	next, _ = m.updateRecon("left")
	m = next.(model)
	if m.reconCardFocus || m.reconMenuFocus {
		t.Fatal("left did not return to hosts")
	}
}

func TestReconCardActionsVisibleOnSmallTerminal(t *testing.T) {
	m := workspaceFixture()
	m.screen = "recon"
	m.width, m.height = 55, 18
	m.reconCardFocus = true
	for i, label := range reconCardActions {
		m.reconHostAction = i
		view := ansi.Strip(m.View())
		if !strings.Contains(view, label) || !strings.Contains(view, "▶") {
			t.Fatalf("action %q hidden:\n%s", label, view)
		}
	}
}

func TestReconInformationIncludesSavedMachineFacts(t *testing.T) {
	m := workspaceFixture()
	host := m.selectedReconHost()
	svc := &m.inventory[host].services[0]
	svc.OS = "Windows Server 2022"
	svc.DeviceType = "server"
	svc.DetectedHostname = "dc01.example.test"
	svc.Info = "domain controller banner"
	svc.CPE = []string{"cpe:/o:microsoft:windows_server_2022"}
	m.hostNames = map[string][]string{host: {"dc01.example.test"}}
	info := strings.Join(m.reconInformation(host, 120), "\n")
	for _, want := range []string{"Windows Server 2022", "dc01.example.test", "domain controller banner", "cpe:/o:microsoft:windows_server_2022", "445/tcp", "Microsoft Windows Server", "Риски:"} {
		if !strings.Contains(info, want) {
			t.Fatalf("missing %q in %s", want, info)
		}
	}
}

func TestReconInformationScrollKeepsActionsAndHost(t *testing.T) {
	m := workspaceFixture()
	m.screen = "recon"
	m.width, m.height = 100, 24
	m.reconCardFocus = true
	host := m.selectedReconHost()
	for i := 0; i < 50; i++ {
		next, _ := m.updateRecon("pgdown")
		m = next.(model)
	}
	offset := m.reconInfoOffset
	next, _ := m.updateRecon("pgup")
	m = next.(model)
	if m.reconInfoOffset >= offset || m.selectedReconHost() != host {
		t.Fatal("scroll failed or changed host")
	}
	if !strings.Contains(ansi.Strip(m.reconCard(60)), "Подключиться") {
		t.Fatal("scroll hid actions")
	}
	next, _ = m.updateRecon("left")
	m = next.(model)
	next, _ = m.updateRecon("down")
	m = next.(model)
	if m.reconInfoOffset != 0 {
		t.Fatal("new machine retained scroll")
	}
}

func TestHostTableShowsFactsWithoutOpeningCard(t *testing.T) {
	m := workspaceFixture()
	m.height = 40
	host := m.reconHosts()[0]
	m.hostNames = map[string][]string{host: {"dc01.example.test"}}
	m.inventory[host].services[0].OS = "Windows Server 2022"
	view := ansi.Strip(m.reconHostList(160))
	for _, want := range []string{host, "dc01.example.test", "Windows Server 2022", "445/tcp smb"} {
		if !strings.Contains(view, want) {
			t.Fatalf("table missing %q:\n%s", want, view)
		}
	}
}

func TestHostTableOmitsEmptyCountersAndExplanations(t *testing.T) {
	m := workspaceFixture()
	row := strings.Join(m.reconHostRow(m.reconHosts()[0]), "\n")
	for _, unwanted := range []string{"Риски:", "Сведения:", "Ошибки:", "не определена", "не обнаружены", "Результаты: 0"} {
		if strings.Contains(row, unwanted) {
			t.Fatalf("extra table text %q: %s", unwanted, row)
		}
	}
}

func TestHostListUsesOneLinePerMachine(t *testing.T) {
	m := workspaceFixture()
	m.height = 24
	for _, host := range m.reconHosts() {
		if row := m.reconHostRow(host); len(row) != 1 || strings.Contains(row[0], "\n") {
			t.Fatalf("multiline machine: %v", row)
		}
	}
	count := -1
	for i := range m.reconHosts() {
		m.reconIndex = i
		view := m.reconHostList(80)
		rows := strings.Count(view, "\n")
		if count >= 0 && rows != count {
			t.Fatal("host list height changes with selection")
		}
		count = rows
		if !strings.Contains(ansi.Strip(view), m.reconHosts()[i]) {
			t.Fatal("selected machine hidden")
		}
	}
}

func TestSidebarDigitsMatchVisibleProjectMenu(t *testing.T) {
	for _, test := range []struct{ key, screen string }{
		{"1", "desk"}, {"2", "guided-scan"}, {"3", "ad-menu"},
		{"4", "input"}, {"5", "credentials"}, {"6", "jobs"},
		{"7", "project-results"}, {"8", "checks-menu"}, {"9", "settings"}, {"0", "projects"},
	} {
		m := newTestModelForSettings(t)
		m.screen = "recon"
		m.sidebarEnabled = true
		m.reconMenuFocus = false
		next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(test.key)})
		m = next.(model)
		if cmd != nil || m.screen != test.screen {
			t.Fatalf("%s opened %s, want %s", test.key, m.screen, test.screen)
		}
		if test.key == "4" && m.inputAction != "add-target" {
			t.Fatal("4 did not add target")
		}
	}
	m := workspaceFixture()
	m.screen = "recon"
	m.height = 50
	m.reconMenuIndex = 10
	view := ansi.Strip(m.viewSidebar(30))
	for _, label := range []string{"1 Машины", "2 Сканировать", "3 AD-разведка", "4 Добавить цель", "5 Учётки", "6 Задачи", "7 Результаты", "8 Проверки", "9 Настройки", "0 Проекты"} {
		if !strings.Contains(view, label) {
			t.Fatalf("digit missing: %s", label)
		}
	}
}

func TestSidebarDigitsDoNotInterceptInputOrConfirmation(t *testing.T) {
	m := workspaceFixture()
	m.sidebarEnabled = true
	for _, screen := range []string{"input", "mssql-console", "winrm-shell", "delete-confirm"} {
		m.screen = screen
		if _, _, ok := m.selectSidebarShortcut("4"); ok {
			t.Fatalf("intercepted input on %s", screen)
		}
	}
	m.screen = "project-results"
	m.resultDeleteConfirm = true
	if _, _, ok := m.selectSidebarShortcut("4"); ok {
		t.Fatal("intercepted confirmation")
	}
}

func TestSidebarLetterShortcuts(t *testing.T) {
	m := workspaceFixture()
	m.sidebarEnabled = true
	m.screen = "recon"
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	m = next.(model)
	if m.screen != "host-selection" {
		t.Fatal("f did not open machine selection")
	}
	m.screen = "ad-menu"
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	m = next.(model)
	if m.screen != "desk" {
		t.Fatal("b did not return")
	}
	for _, screen := range []string{"desk", "ad-menu", "project-results", "recon"} {
		m.screen = screen
		next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
		opened := next.(model)
		if opened.screen != "port-browser" || opened.portBrowserReturn != screen || cmd != nil {
			t.Fatalf("p from %s did not open ports without starting a task", screen)
		}
	}
	m.screen = "project-results"
	if _, _, ok := m.selectSidebarShortcut("f"); ok {
		t.Fatal("menu shortcut hijacked results filter")
	}
	m.reconMenuFocus = true
	if _, _, ok := m.selectSidebarShortcut("f"); !ok {
		t.Fatal("menu filter inaccessible")
	}
	m.screen = "input"
	for _, key := range []string{"f", "b", "p"} {
		if _, _, ok := m.selectSidebarShortcut(key); ok {
			t.Fatalf("%s intercepted input", key)
		}
	}
	m.screen = "ad-menu"
	m.height = 50
	view := ansi.Strip(m.viewSidebar(32))
	if !strings.Contains(view, "f Выбор машин") || !strings.Contains(view, "b ← Назад") || !strings.Contains(view, "p Порты") {
		t.Fatal("letter labels missing")
	}
}
