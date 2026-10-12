package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"wscan/internal/catalog"
)

var headingStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#67E8C5"))
var messageStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F6C177"))
var brandStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#67E8C5"))
var mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#82949A"))
var focusedBorder = lipgloss.Color("#5EEAD4")
var idleBorder = lipgloss.Color("#29434A")

// bruteTagStyle marks a catalog entry classified as credential-guessing
// (library/tools/gen_categories.py's "Подбор учётных данных" type, which
// spans http/default-logins, javascript/default-logins, network/default-login
// and NSE's own "brute" category) — a short inline badge so this stands out
// when browsing by service/impact (the "а что это" axis) without having to
// switch to the "by type" axis just to tell brute-force checks apart from
// passive detectors.
var bruteTagStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F6C177"))

const bruteCategoryLabel = "Подбор учётных данных"

func isBruteEntry(e catalog.Entry) bool {
	path := strings.ToLower(e.Path)
	return strings.Contains(e.Type, bruteCategoryLabel) ||
		strings.Contains(e.Category, bruteCategoryLabel) ||
		strings.Contains(path, "/credential-stuffing/") ||
		strings.Contains(path, "wp-xmlrpc-brute-force")
}

func checkMark(on bool) string {
	if on {
		return "[✓]"
	}
	return "[ ]"
}

func statusIcon(status string) string {
	switch status {
	case statusRunning:
		return "⟳"
	case statusDone:
		return "✓"
	case statusFailed:
		return "✗"
	case statusCancelled:
		return "⊘"
	}
	return "·"
}

func (m model) View() string {
	w, h := m.width, m.height
	if w <= 0 {
		w = 100
	}
	if h <= 0 {
		h = 24
	}
	header := brandStyle.Render("WSCAN")
	if m.current.ID > 0 && m.screen != "projects" && m.screen != "ad-scan" {
		header += mutedStyle.Render("  /  " + m.current.Name)
	}

	var body string
	switch m.screen {
	case "ssh-password-lists":
		body = m.viewSSHPasswordLists(w)
	case "ssh-dictionary":
		body = m.viewSSHDictionary(w)
	case "web-wordlists":
		body = m.viewWebWordlists(w)
	case "web-discovery":
		body = m.viewWebDiscovery(w)
	case "sqli-form":
		body = m.viewSQLiForm(w)
	case "file-upload":
		body = m.viewFileUpload(w)
	case "interaction-targets":
		body = m.viewInteractionTargets(w)
	case "ftp-setup":
		body = m.viewFTPSetup(w)
	case "ftp-browser":
		body = m.viewFTPBrowser(w)
	case "smb-setup":
		body = m.viewSMBCredentials(w)
	case "lfi-audit":
		body = m.viewLFI(w)
	case "mysql-setup", "mysql-console":
		body = m.viewMySQL(w)
	case "pg-setup", "pg-console":
		body = m.viewPG(w)
	case "mssql-setup", "mssql-console", "mssql-actions", "mssql-xp-confirm":
		if m.screen == "mssql-actions" || m.screen == "mssql-xp-confirm" {
			body = m.viewMSSQLActions(w)
		} else {
			body = m.viewMSSQL(w)
		}
	case "winrm-shell":
		body = m.viewWinRMShell(w)
	case "winrm-setup":
		body = m.viewWinRMSetup(w)
	case "winrm-browser":
		body = m.viewWinRMBrowser(w)
	case "kyocera-book":
		body = m.viewKyocera(w)
	case "interaction-menu":
		body = m.viewInteractionMenu(w)
	case "smb-browser":
		body = m.viewSMBBrowser(w)
	case "project-delete-confirm":
		body = m.viewProjectDelete(w)
	case "projects":
		body = m.viewProjects(w)
	case "ad-scan":
		body = m.viewADScan(w)
	case "coerce-port-check", "coerce-port-confirm", "coerce-port-stopping":
		body = m.viewCoercionPort(w)
	case "coerce-setup":
		body = m.viewCoercionSetup(w)
	case "ad-access":
		body = m.viewADAccess(w)
	case "host-port-selection":
		body = m.viewHostPortSelection(w)
	case "host-selection":
		body = m.viewHostSelection(w)
	case "desk":
		body = m.viewDesk(w)
	case "service-inventory":
		body = m.viewServiceInventory(w, m.bodyHeight())
	case "networks":
		body = m.viewNetworks(w)
	case "action-menu":
		body = m.viewActionMenu(w)
	case "disc-options":
		body = m.viewDiscOptions(w)
	case "jobs":
		body = m.viewJobs(w)
	case "job-details":
		body = m.viewJobDetails(w)
	case "finding-details", "project-results":
		body = m.viewFindingDetails(w)
	case "scan-review":
		body = m.viewScanReview(w)
	case "catalog-groups":
		body = m.viewCatalogGroups(w)
	case "catalog":
		body = m.viewCatalog(w)
	case "dependency-settings":
		body = m.viewDependencySettings(w)
	case "dependency-install-confirm":
		body = m.viewDependencyInstallConfirm(w)
	case "library-settings":
		body = m.viewLibrarySettings(w)
	case "global-settings":
		body = m.viewGlobalSettings(w)
	case "settings":
		body = m.viewSettings(w)
	case "speed-presets":
		body = m.viewSpeedPresets(w)
	case "delete-confirm":
		body = m.viewDelete(w)
	case "code-exec-confirm":
		body = m.viewCodeExecConfirm(w)
	case "exploit-confirm":
		body = m.viewExploitConfirm(w)
	case "credential-attack-confirm":
		body = m.viewCredentialAttackConfirm(w)
	case "credentials":
		body = m.viewCredentials(w)
	case "cred-add-type":
		body = m.viewCredAddType(w)
	case "cred-delete-confirm":
		body = m.viewCredDeleteConfirm(w)
	case "spray-setup":
		body = m.viewSpraySetup(w)
	case "spray-running":
		body = m.viewSprayRunning(w)
	case "spray-results":
		body = m.viewSprayResults(w)
	case "spray-module-picker":
		body = m.viewSprayModulePicker(w)
	case "spray-module-result":
		body = m.viewSprayModuleResult(w)
	case "history":
		body = m.viewHistory(w)
	case "repair-target":
		body = m.viewRepair(w)
	case "input":
		body = m.viewInput(w)
	case "help":
		body = m.viewHelp(w)
	}
	lines := []string{
		fitContent(header, w, 1),
		fitContent(m.navigationLine(), w, 1),
		fitContent(m.contextLine(), w, 1),
		fitContent(body, w, m.bodyHeight()),
		fitContent(m.activityLine(), w, 1),
		fitContent(messageStyle.Render(m.message), w, 1),
		fitContent(mutedStyle.Render(m.footer()+"   ·   ? помощь"), w, 1),
	}
	return fitContent(strings.Join(lines, "\n"), w, h)
}

// Always reserve room for the header, job activity, message and key hints.
func (m model) bodyHeight() int {
	height := m.height
	if height <= 0 {
		height = 24
	}
	return max(1, height-6)
}

func fitContent(content string, width, height int) string {
	lines := strings.Split(content, "\n")
	out := make([]string, max(1, height))
	for i := range out {
		if i < len(lines) {
			out[i] = ansi.Truncate(lines[i], max(1, width), "")
		}
		out[i] += strings.Repeat(" ", max(0, width-ansi.StringWidth(out[i])))
	}
	return strings.Join(out, "\n")
}

func (m model) activityLine() string {
	running, done, failed := m.countJobs()
	prefix := fmt.Sprintf("Задачи: %d в работе · %d завершено · %d ошибок · g открыть", running, done, failed)
	for _, j := range m.jobs {
		if j.active() {
			return headingStyle.Render("g — Задачи ") + j.scope + " " + j.progressText(10) + "  " + j.stage + fmt.Sprintf(" · %s · ещё в работе: %d", j.duration().Round(time.Second), running-1)
		}
	}
	if n := m.unseenDone(); n > 0 {
		prefix += fmt.Sprintf(" · %d новых результатов", n)
	}
	return mutedStyle.Render(prefix)
}

func (m model) footer() string {
	switch m.screen {
	case "coerce-setup":
		if m.adAccessJobRunning() {
			return "Esc остановить проверку · g задачи"
		}
		return "↑/↓ действие · Enter выполнить · c учётка · p приёмник · r адрес · Esc назад"
	case "coerce-port-check", "coerce-port-stopping":
		return "Esc отменить запуск"
	case "coerce-port-confirm":
		return "Enter / y остановить владельца порта · Esc / n отменить"
	case "ad-access":
		return "↑/↓ проверка · Enter запуск · c учётка · h хост · r приёмник · p Responder · Esc назад/отмена"
	case "interaction-targets":
		return "↑/↓ машина · Enter выбрать · Esc назад"
	case "mysql-setup", "pg-setup":
		return "↑/↓ учётка · Enter подключиться · p порт · c учётки · Esc назад"
	case "mysql-console", "pg-console":
		return "↑/↓ выбор · Enter действие · PgUp/PgDn текст · Esc назад"
	case "ssh-dictionary":
		return "s / Enter запуск · u пользователь · p словарь · r скорость · Esc назад/отмена"
	case "ssh-password-lists":
		return "↑/↓ словарь · Enter выбрать · f путь · Esc назад"
	case "web-discovery":
		return "s запуск · u URL · w словарь · ↑/↓ результаты · e экспорт · Esc назад/отмена"
	case "web-wordlists":
		return "↑/↓ словарь · / поиск · Enter выбрать · p путь · Esc назад"
	case "sqli-form", "file-upload":
		return "s проверить · u URL · c учётка · ↑/↓ результаты · e экспорт · Esc назад/отмена"
	case "ftp-setup":
		return "↑↓ учётка · Enter вход · c Credentials · p порт · s FTP/FTPS · t сертификат · Esc назад"
	case "ftp-browser":
		if m.ftpBrowser.preview != "" {
			return "↑↓/PgUp/PgDn текст · d скачать · Esc к файлам"
		}
		return "Enter открыть · ← вверх · d скачать · p путь · c учётка · e CSV · r обновить · Esc выход/отмена"
	case "mssql-setup":
		return "↑↓ учётка · Enter вход · p порт · s TLS · t сертификат · c Credentials · Esc назад"
	case "mssql-actions":
		return "↑/↓ выбор · Enter действие · Esc результаты"
	case "mssql-xp-confirm":
		return "Enter включить xp_cmdshell · Esc отмена"
	case "mssql-console":
		return "1–8 аудит · Enter меню · c SQL · b база · n NSE · ↑↓/PgUp/PgDn текст · Esc закрыть"
	case "smb-setup":
		return "↑↓ учётка · Enter вход · c Credentials · Esc назад"
	case "lfi-audit":
		return "u URL · p параметр · v virtual host · t TLS · Enter проверить · Esc назад/отмена"
	case "kyocera-book":
		return "p порт · w пауза · t TLS · Enter получить · Esc назад/отмена"
	case "winrm-shell":
		return "Enter/c команда · ↑↓/PgUp/PgDn вывод · Home/End · Esc закрыть PowerShell"
	case "winrm-setup":
		return "↑↓ учётка · Enter подключиться · s HTTP/HTTPS · p порт · t сертификат · c Credentials · Esc назад"
	case "winrm-browser":
		if m.winrmBrowser.output != "" {
			return "↑↓/PgUp/PgDn текст · Esc к файлам"
		}
		return "Enter открыть · ← вверх · d скачать · a ACL · c одна команда · s PowerShell-сессия · u права · p путь · e CSV · r обновить · Esc выход"
	case "interaction-menu":
		return "↑↓ выбор · Enter открыть · Esc хосты"
	case "smb-browser":
		if m.smbBrowser.preview != "" {
			return "↑↓/PgUp/PgDn текст · d скачать · Esc к файлам"
		}
		return "↑↓ выбор · Enter открыть · ← назад · d скачать · e CSV · a null/guest · c учётка · f конфигурации · r обновить · Esc выход/отмена"
	case "project-delete-confirm":
		return "Enter удалить проект · Esc отмена"
	case "projects":
		return "↑/↓ проект   Enter открыть   p общие настройки   n создать   Del удалить   d AD-аудит → новый проект   g задачи   q выход"
	case "ad-scan":
		if m.adScanRunning {
			return "x / Esc остановить сканирование"
		}
		if m.adScanResult != nil {
			return "↑/↓ результаты   r выбрать подсеть заново   Enter повторить скан   Esc назад"
		}
		return "↑/↓ интерфейс   Enter сканировать выбранную подсеть   r обновить   x остановить   Esc назад"
	case "host-port-selection", "host-selection":
		return "↑↓ выбор · Enter применить · Esc назад"
	case "desk":
		if m.width > 0 && m.width < 88 {
			return "←→ панель · ↑/↓ выбор · Enter действие · v сервисы · Space выбор · f выбрать хосты"
		}
		return "←→ панели · ↑/↓ выбор · Enter действие · v сервисы · i взаимодействие · Space выбор · f выбрать хосты · a хост · Del удалить"
	case "service-inventory":
		if m.serviceInventoryEditing {
			return "Ввод фильтра · Enter готово · Esc отменить ввод"
		}
		return "↑/↓ сервис · / фильтр · Space выбрать хост · a выбрать все · x очистить · Enter действие · Esc назад"
	case "networks":
		if m.width > 0 && m.width < 88 {
			return "Enter действия · o хосты подсети · a CIDR · Space выбор · f выбрать хосты"
		}
		return "↑/↓ выбор · Enter действия · o хосты · a CIDR · Space выбор · Del удалить"
	case "action-menu":
		if hasNetworkTarget(m.actionHosts) {
			return "↑/↓ выбрать действие   Enter продолжить   Esc назад"
		}
		return "↑/↓ выбор   Space выбрать проверки   Enter запустить   Esc назад"
	case "disc-options":
		return "↑/↓ параметр · ←/→/Space изменить · e значение · Enter запуск · Esc назад"
	case "jobs":
		return "↑/↓ задача   Enter подробности и лог   x отменить   c очистить   e экспорт   Esc назад"
	case "job-details":
		if !m.jobDetailRaw {
			if m.jobIndex >= 0 && m.jobIndex < len(m.jobs) && m.jobs[m.jobIndex].opensHostResults() {
				return "Enter хосты и порты · r журнал · x отменить · e экспорт · Esc задачи"
			}
			return "Enter результаты · r журнал · x отменить · e экспорт · Esc задачи"
		}
		return "↑/↓ журнал   Enter результаты   r журнал/итог   x отменить   e экспорт   Esc задачи"
	case "project-results":
		if m.resultDeleteConfirm {
			return "Enter подтвердить удаление · Esc отменить"
		}
		if m.findingPane == 1 {
			back := "список"
			if m.findingDirectReturn {
				back = "назад"
			}
			if m.splitResultDetails(m.width) {
				return "←/→ панель · ↑/↓ выбор/прокрутка · Tab раздел · r отчёт · Esc " + back
			}
			return "Tab раздел · r отчёт · [/] находки · ↑/↓ прокрутка · Esc " + back
		}
		return "Enter карточка · Del/d удалить · / поиск · f фильтр · Esc назад · Space отметить · v порты"
	case "finding-details":
		return "↑/↓ выбор/прокрутка · Enter подробности · Del удалить · r технические данные · Esc назад"
	case "scan-review":
		return "↑/↓ параметр   ←/→ пресет   Enter выбрать   Home запуск   Esc проверки   g задачи"
	case "catalog-groups":
		if m.catalogReadOnly {
			return "↑/↓ категория   Enter/→ внутрь   1 тип · 2 продукт · 3 сервис   / поиск   Esc назад"
		}
		if m.catalogPending {
			return "↑/↓ категория   → внутрь   Space отметить   Enter запуск   A всё   x снять   1 тип · 2 продукт · 3 сервис   / поиск   ← назад"
		}
		return "↑/↓ категория   Space отметить   →/Enter внутрь   A всё   x снять   1 тип · 2 продукт · 3 сервис   / поиск   ←/Esc назад"
	case "catalog":
		if m.catalogReadOnly {
			return "↑/↓ проверка   / поиск   ←/Esc категории"
		}
		if m.catalogPending {
			return "↑/↓ проверка   Space выбрать   Enter запуск   A вся группа   x снять   / поиск   ← категории"
		}
		return "↑/↓ проверка   Space/Enter выбрать   A вся группа   x снять   / поиск   ←/Esc категории"
	case "dependency-settings":
		return "↑/↓ интерпретатор   Enter установить   r проверить   Esc настройки"
	case "dependency-install-confirm":
		return "Enter установить / скачать   Esc отмена"
	case "library-settings":
		return "Enter скачать / обновить   t скачанные проверки   Esc настройки"
	case "global-settings":
		return "↑/↓ раздел   Enter открыть   Esc проекты"
	case "settings":
		return "↑/↓ настройка   ←/→ переключить   Enter изменить   Esc стол"
	case "speed-presets":
		return "↑/↓ или ←/→ пресет   Enter применить   Esc назад"
	case "delete-confirm":
		return "Enter удалить   Esc отмена"
	case "code-exec-confirm":
		return "Enter разрешить   Esc отмена"
	case "exploit-confirm":
		return "Enter разрешить   Esc отмена"
	case "credential-attack-confirm":
		return "Enter разрешить   Esc отмена"
	case "credentials":
		return "↑/↓ выбор   a добавить   e/Enter редактировать   g anonymous/null session   d удалить   Esc стол"
	case "cred-add-type":
		return "←/→ тип   Enter далее   Esc отмена"
	case "cred-delete-confirm":
		return "Enter удалить   Esc отмена"
	case "spray-setup":
		return "↑/↓ credential   Space отметить   A все   N снять все   Enter запуск   Esc отмена"
	case "spray-running":
		return ""
	case "spray-results":
		return "↑/↓ попытка   m запустить модуль (для успешных)   Esc стол"
	case "spray-module-picker":
		return "↑/↓ модуль   Enter запустить   Esc назад"
	case "spray-module-result":
		return "Enter/Esc назад к результатам"
	case "history":
		return "↑/↓ запуск   Enter результаты запуска   e экспорт   Esc стол"
	case "repair-target":
		return "Enter исправить   Esc отмена"
	case "input":
		return "Enter сохранить   Ctrl+U очистить   Esc отмена"
	case "help":
		return "Enter / Esc закрыть"
	}
	return ""
}

func (m model) viewProjects(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("Проекты") + "\n")
	body.WriteString("Выбери рабочий проект\n[p] Общие настройки: библиотека, Python и Ruby\n[Del / D] Удалить выбранный проект\n\n")
	if len(m.projects) == 0 {
		body.WriteString("Проектов пока нет. Нажми n, чтобы создать первый.\n")
	} else {
		lo, hi := windowRange(m.selected, len(m.projects), m.panelRows())
		body.WriteString(moreLine(lo, true))
		for i := lo; i < hi; i++ {
			p := m.projects[i]
			line := fmt.Sprintf("%-24s  %2d целей   %2d шаблонов", p.Name, len(p.Targets), len(p.TemplateIDs))
			body.WriteString(renderListRow(line, i == m.selected, w))
		}
		body.WriteString(moreLine(len(m.projects)-hi, false))
	}
	return m.renderPanel(w, body.String())
}

// --- desk: three Miller columns -----------------------------------------

func (m model) viewDesk(w int) string {
	return m.viewHostWorkspace(w)
}

func (m model) viewNetworks(w int) string {
	return m.viewNetworkWorkspace(w)
}

func colBoxStyle(width, height int, focused bool) lipgloss.Style {
	color := idleBorder
	if focused {
		color = focusedBorder
	}
	return lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(color).Padding(0, 1).Width(width + 2).Height(height).MaxHeight(height + 2)
}

// windowRange centers a visible slice [lo,hi) of `count` rows on `pivot`,
// so long lists scroll instead of overflowing a fixed-height column.
func windowRange(pivot, count, visible int) (lo, hi int) {
	if visible < 1 {
		visible = 1
	}
	if count <= visible {
		return 0, count
	}
	if pivot < 0 {
		pivot = 0
	}
	lo = pivot - visible/2
	if lo < 0 {
		lo = 0
	}
	if lo+visible > count {
		lo = count - visible
	}
	if lo < 0 {
		lo = 0
	}
	hi = lo + visible
	if hi > count {
		hi = count
	}
	return lo, hi
}

func moreLine(n int, up bool) string {
	if n <= 0 {
		return ""
	}
	arrow := "▼"
	if up {
		arrow = "▲"
	}
	return mutedStyle.Render(fmt.Sprintf("  %s ещё %d", arrow, n)) + "\n"
}

func (m model) renderHostsColumn(width, height int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render(fmt.Sprintf("ХОСТЫ (%d)", len(m.hostOrder))) + "\n")
	allPorts, allFindings := 0, 0
	for _, h := range m.hostOrder {
		p, f := m.hostSummary(h)
		allPorts += p
		allFindings += f
	}
	portDigits := max(2, len(fmt.Sprint(allPorts)))
	findingDigits := max(2, len(fmt.Sprint(allFindings)))
	// Include both row padding and the selection marker in the width budget.
	fieldW := max(1, width-4-portDigits-findingDigits-4)
	formatRow := func(label string, ports, findings int) string {
		label = truncateMid(label, fieldW)
		return label + strings.Repeat(" ", max(0, fieldW-ansi.StringWidth(label))) +
			fmt.Sprintf(" %*dП %*dР", portDigits, ports, findingDigits, findings)
	}
	allLine := formatRow("Все в списке · f выбор", allPorts, allFindings)
	body.WriteString(renderListRow(allLine, m.hostIndex == -1, width+4))
	// Budget: box height minus heading, "All hosts" row, and two indicator lines.
	rowHeights := make([]int, len(m.hostOrder))
	for i, host := range m.hostOrder {
		rowHeights[i] = 1
		names := m.namesForHost(host)
		inlineNameWidth := fieldW - 4 - ansi.StringWidth(host) - 1
		if height >= 12 && len(names) > 0 && ansi.StringWidth(names[0]) > inlineNameWidth {
			rowHeights[i] = 2
		}
	}
	lo, hi := variableRowRange(m.hostIndex, rowHeights, max(1, height-4))
	body.WriteString(moreLine(lo, true))
	for i := lo; i < hi; i++ {
		ports, findings := m.hostSummary(m.hostOrder[i])
		mark := "[ ] "
		if m.selectedHosts[m.hostOrder[i]] {
			mark = "[x] "
		}
		label := m.hostOrder[i]
		names := m.namesForHost(label)
		if rowHeights[i] == 1 && len(names) > 0 {
			nameWidth := fieldW - 4 - ansi.StringWidth(label) - 1
			if nameWidth > 0 {
				label += " " + truncateMid(names[0], nameWidth)
			}
		}
		line := formatRow(mark+truncateMid(label, max(1, fieldW-4)), ports, findings)
		body.WriteString(renderListRow(line, i == m.hostIndex, width+4))
		if rowHeights[i] == 2 {
			nameLine := ""
			if len(names) > 0 {
				nameLine = "    " + truncateMid(names[0], max(1, width-8))
			}
			body.WriteString(renderListRow(nameLine, i == m.hostIndex, width+4))
		}
	}
	body.WriteString(moreLine(len(m.hostOrder)-hi, false))
	return renderColumn(body.String(), width, height, m.focusCol == 0)
}

func (m model) renderServicesColumn(width, height int) string {
	var body strings.Builder
	host := m.currentHost()
	title := "ПОРТЫ"
	if host != "" {
		title = "ПОРТЫ — " + truncateMid(host, max(6, width-8))
	}
	body.WriteString(headingStyle.Render(title) + "\n")
	if m.hostIndex < 0 {
		body.WriteString(mutedStyle.Render("Выбери хост, чтобы увидеть порты") + "\n")
		return renderColumn(body.String(), width, height, m.focusCol == 1)
	}
	services := m.servicesFor(host)
	if m.selectedPortMissing() {
		body.WriteString(renderListRow(fmt.Sprintf("%d/%s — не найден", m.preferredPort, m.preferredProtocol), true, width+4))
	}
	if len(services) == 0 {
		body.WriteString(mutedStyle.Render("Портов пока нет.\nНажми Enter → найти порты.") + "\n")
		return renderColumn(body.String(), width, height, m.focusCol == 1)
	}
	_, allFindings := m.hostSummary(host)
	allPortsLine := fmt.Sprintf("%-*s %2dП %2dН", max(8, width-14), "Все порты", len(services), allFindings)
	body.WriteString(renderListRow(allPortsLine, m.serviceIndex < 0 && !m.selectedPortMissing(), width+4))
	// When the host row is a domain that resolved to several IPs, discovery
	// scanned each one, so the same port appears once per address. Show the IP
	// so those rows read as distinct endpoints instead of duplicates.
	multiIP := false
	if host != "" {
		firstIP := ""
		for _, s := range services {
			if s.Host == "" {
				continue
			}
			if firstIP == "" {
				firstIP = s.Host
			} else if s.Host != firstIP {
				multiIP = true
				break
			}
		}
		multiIP = multiIP && host != firstIP
	}
	visible := max(1, height-4)
	if m.selectedPortMissing() {
		visible = max(1, visible-1)
	}
	lo, hi := windowRange(m.serviceIndex, len(services), visible)
	body.WriteString(moreLine(lo, true))
	for i := lo; i < hi; i++ {
		line := serviceLabel(services[i])
		switch status := m.serviceCheckStatus(host, services[i]); {
		case strings.HasPrefix(status, "Выполняются"):
			line += " · скан"
		case strings.HasPrefix(status, "Завершены с ошибками"), strings.HasPrefix(status, "Ошибка"):
			line += " · ошибки"
		case strings.HasPrefix(status, "Завершены"):
			line += " · готово"
		case strings.HasPrefix(status, "Остановлены"):
			line += " · остановлено"
		}
		if multiIP && services[i].Host != "" {
			line += " · " + services[i].Host
		}
		if n := len(m.findingsForService(host, services[i])); n > 0 {
			line += fmt.Sprintf("  [%d]", n)
		}
		body.WriteString(renderListRow(line, i == m.serviceIndex, width+4))
	}
	body.WriteString(moreLine(len(services)-hi, false))
	return renderColumn(body.String(), width, height, m.focusCol == 1)
}

func (m model) renderDetailsColumn(width, height int) string {
	var body strings.Builder
	compact := height < 18
	body.WriteString(headingStyle.Render("РЕЗУЛЬТАТЫ") + "\n")
	host := m.currentHost()
	if host == "" {
		body.WriteString(mutedStyle.Render("Выбери хост слева"))
		return renderColumn(body.String(), width, height, m.focusCol == 2)
	}
	if names := m.namesForHost(host); len(names) > 0 && !compact {
		fmt.Fprintf(&body, "DNS: %s\n", strings.Join(names, ", "))
	}
	services := m.servicesFor(host)
	if m.selectedPortMissing() {
		fmt.Fprintf(&body, "%d/%s не найден у %s.\nВыбор порта сохранён для следующего хоста.", m.preferredPort, m.preferredProtocol, host)
		return renderColumn(body.String(), width, height, m.focusCol == 2)
	}
	if m.serviceIndex < 0 || m.serviceIndex >= len(services) || len(services) == 0 {
		findings := m.findingsFor(host)
		if m.serviceIndex < 0 && len(services) > 0 {
			fmt.Fprintf(&body, "Все порты хоста: %d\n", len(services))
		}
		if len(findings) == 0 {
			if m.serviceIndex < 0 {
				body.WriteString(mutedStyle.Render("Находки не зарегистрированы. Enter — выбрать проверки по найденным портам."))
			} else {
				body.WriteString(mutedStyle.Render("Нет выбранного порта."))
			}
		} else {
			body.WriteString(ansi.Truncate(resultCounts(findings), width, "…") + "\n")
			body.WriteString(mutedStyle.Render("Enter — подробно") + "\n")
			visible := max(1, height-lipgloss.Height(wrapPaneBody(body.String(), width))-2)
			lo, hi := windowRange(m.findingIndex, len(findings), visible)
			for i := lo; i < hi; i++ {
				body.WriteString(renderFindingRow(findings[i], i == m.findingIndex, width+4))
			}
			body.WriteString(moreLine(len(findings)-hi, false))
		}
		return renderColumn(body.String(), width, height, m.focusCol == 2)
	}
	s := services[m.serviceIndex]
	if compact {
		body.WriteString(ansi.Truncate(fmt.Sprintf("%s:%d · %s", s.Host, s.Port, s.Name), width, "…") + "\n")
	} else {
		fmt.Fprintf(&body, "%s:%d\nПроверки: %s\n", s.Host, s.Port, m.serviceCheckStatus(host, s))
	}
	serviceName := s.Name
	if serviceName == "" {
		serviceName = "не определён"
	}
	if !compact {
		fmt.Fprintf(&body, "Сервис: %s (%s)\n", serviceName, s.Protocol)
	}
	if s.PortService != "" && !compact {
		fmt.Fprintf(&body, "По порту: %s (nmap-services)\n", s.PortService)
	}
	if s.Product != "" && !compact {
		fmt.Fprintf(&body, "Продукт: %s %s\n", s.Product, s.Version)
	}
	findings := m.findingsForService(host, s)
	if !compact {
		for _, line := range smbSummary(findings) {
			body.WriteString(line + "\n")
		}
	}
	if len(findings) == 0 {
		if errors := m.serviceResultErrors(host, s); errors > 0 {
			body.WriteString(resultCounts(findings, errors) + "\nОшибки проверок — g, журнал задачи.\nEnter — выбрать проверки для этого порта.")
		} else {
			body.WriteString(mutedStyle.Render("Результатов пока нет. Enter — выбрать проверки для этого порта."))
		}
	} else {
		if !compact {
			body.WriteString("\nПОСЛЕДНИЕ РЕЗУЛЬТАТЫ\n")
		}
		body.WriteString(ansi.Truncate(resultCounts(findings, m.serviceResultErrors(host, s)), width, "…") + "\n")
		if m.serviceResultErrors(host, s) > 0 {
			body.WriteString("g — журнал ошибок задачи\n")
		}
		body.WriteString(mutedStyle.Render("Enter — подробно") + "\n")
		// Header block above already consumed ~9 lines; window the rest.
		visible := max(1, height-lipgloss.Height(wrapPaneBody(body.String(), width))-2)
		lo, hi := windowRange(m.findingIndex, len(findings), visible)
		body.WriteString(moreLine(lo, true))
		for i := lo; i < hi; i++ {
			body.WriteString(renderFindingRow(findings[i], i == m.findingIndex, width+4))
		}
		body.WriteString(moreLine(len(findings)-hi, false))
	}
	return renderColumn(body.String(), width, height, m.focusCol == 2)
}

func truncateMid(s string, n int) string {
	if n <= 1 || len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// --- action menu --------------------------------------------------------

func (m model) viewActionMenu(w int) string {
	var body strings.Builder
	if m.actionService != nil {
		s := *m.actionService
		body.WriteString(headingStyle.Render("Действие на порту") + "\n")
		fmt.Fprintf(&body, "%s:%d  %s\n\n", s.Host, s.Port, serviceLabel(s))
	} else {
		title := "Действия с хостами"
		if hasNetworkTarget(m.actionHosts) {
			title = "Действия с подсетью"
		}
		body.WriteString(headingStyle.Render(title) + "\n")
		fmt.Fprintf(&body, "Цели: %s\n\n", strings.Join(m.actionHosts, ", "))
	}
	for i, row := range m.actionRows() {
		line := row.title
		if row.needsPicker {
			line = fmt.Sprintf("%s · %d выбрано", row.title, len(m.pendingTemplateIDs))
		}
		body.WriteString(renderListRow(line, i == m.actionIndex, dialogWidth("action-menu", w)))
	}
	return m.renderPanel(w, body.String())
}

func (m model) viewDiscOptions(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("Сканирование портов") + "\n")
	fmt.Fprintf(&body, "Цели: %s\n\n", strings.Join(m.discHosts, ", "))
	setLabel := discSetLabels[m.discSetIndex]
	rows := []string{
		"Набор портов:  " + setLabel,
		checkMark(m.discTCP) + "  TCP скан",
		checkMark(m.discUDP) + "  UDP скан (best-effort)",
		checkMark(m.discVersion) + "  Определять версии сервисов",
		"Запустить",
		"Пресет скорости: " + portSpeedName(m.discProject),
		fmt.Sprintf("Проб/сек: %d (0 — без лимита)", m.discProject.DiscoveryRPS),
		fmt.Sprintf("Параллельность: %d", m.discProject.DiscoveryConcurrency),
		"Добавлять: " + portResultPolicy(m.discOnlyKnown),
		checkMark(m.discNoPing) + "  -Pn: пропустить host discovery и сканировать все адреса",
	}
	lo, hi := windowRange(m.discOptIndex, len(rows), max(1, m.bodyHeight()-8))
	body.WriteString(moreLine(lo, true))
	for i := lo; i < hi; i++ {
		body.WriteString(renderListRow(rows[i], i == m.discOptIndex, min(w, 96)))
	}
	body.WriteString(moreLine(len(rows)-hi, false))
	if m.bodyHeight() > 16 {
		body.WriteString("\nДобавляются только открытые порты.\n")
	}
	if m.discSetIndex == 4 && m.bodyHeight() > 18 {
		custom := m.discCustom
		if custom == "" {
			custom = "(пусто — e на «Набор портов»)"
		}
		body.WriteString("\n" + mutedStyle.Render("Свой список: "+custom))
	}
	return m.renderPanel(w, body.String())
}

// --- jobs -----------------------------------------------------------------

func (m model) viewJobs(w int) string {
	var body strings.Builder
	rows := m.jobs
	body.WriteString(headingStyle.Render(fmt.Sprintf("Задачи сканирования (%d)", len(rows))) + "\n\n")
	if len(rows) == 0 {
		body.WriteString(mutedStyle.Render("Пока ничего не запускалось. Esc → стол, Enter → сканирование."))
		return m.renderPanel(w, body.String())
	}
	body.WriteString(mutedStyle.Render("Прогресс текущего этапа · x отменить · Enter итог задачи") + "\n\n")
	lo, hi := windowRange(m.jobIndex, len(rows), max(1, (m.panelRows()-2)/2))
	body.WriteString(moreLine(lo, true))
	for i := lo; i < hi; i++ {
		j := rows[i]
		dur := j.duration().Round(time.Second)
		scope := j.scope
		if scope == "" {
			scope = j.label
		}
		line := fmt.Sprintf("%s #%d %s · %s / %s · %s", statusIcon(j.status), j.id, scope, m.findProject(j.projectID).Name, j.label, dur)
		if j.status == statusDone {
			if !j.opensHostResults() || j.findings > 0 {
				line += fmt.Sprintf("  результатов: %d", j.findings)
			}
			if !j.seen {
				line += "  •новое"
			}
		}
		if j.errText != "" {
			line += "  " + j.errText
		}
		body.WriteString(renderListRow(line, i == m.jobIndex, w))
		summary := j.progressText(min(20, max(3, w/6))) + "  " + j.stage
		if j.result != nil {
			if discovered := j.discoverySummary(); discovered != "" {
				summary = discovered + " · " + j.stage
			}
		}
		body.WriteString(renderListRow("  "+summary, false, w))
	}
	body.WriteString(moreLine(len(rows)-hi, false))
	return m.renderPanel(w, body.String())
}

// --- catalog ---------------------------------------------------------------

func (m model) viewCatalogGroups(w int) string {
	var body strings.Builder
	title := "Какие проверки провести"
	if m.catalogReadOnly {
		title = "Скачанные проверки"
	}
	body.WriteString(headingStyle.Render(title) + "\n")
	grouped := "по типу проверки"
	if m.catalogAxis == "impact" {
		grouped = "по воздействию · " + m.catalogDirection
	}
	if m.catalogAxis == "database" {
		grouped = "по типу БД"
	}
	if m.catalogDatabase != "" {
		grouped += " · " + m.catalogDatabase
	}
	if m.catalogAxis == "direction" {
		grouped = "по сервису"
	}
	if m.catalogAxis == "product" {
		grouped = "по продукту / сервису"
	}
	fmt.Fprintf(&body, "Группировка: %s   (1 тип · 2 продукт · 3 сервис)\n", grouped)
	if m.catalogAxis == "impact" {
		body.WriteString("Обнаружение тоже отправляет запросы. Сильное: fuzzing, brute, эксплуатация, DoS.\n")
	}
	if m.catalogAxis == "direction" {
		body.WriteString("Неподдерживаемые движком проверки — в отдельной категории внизу списка.\n")
	}
	if m.catalogPending {
		body.WriteString(m.selectionScope() + "\n")
	}
	if m.librarySyncing {
		body.WriteString(mutedStyle.Render("Скачиваю библиотеку шаблонов…") + "\n")
	} else {
		body.WriteString(mutedStyle.Render("Скачать шаблоны: Общие настройки → Библиотека\n"))
	}
	if m.search != "" {
		body.WriteString("Поиск: " + m.search + "\n")
	}
	if m.catalogReadOnly {
		body.WriteString(mutedStyle.Render("Просмотр скачанных проверок · Enter/→ — открыть · / поиск") + "\n")
	} else if m.catalogPending {
		body.WriteString(mutedStyle.Render("Space — отметить · → — внутрь · Enter — запуск · A всё · x снять · / поиск") + "\n")
	} else {
		body.WriteString(mutedStyle.Render("Space — отметить · →/Enter — открыть · A всё · x снять · / поиск") + "\n")
	}
	groups := m.visibleCatalogGroups()
	total, selected := m.groupCounts()
	lo, hi := windowRange(min(m.catalogGroupIndex, max(0, len(groups)-1)), len(groups), max(1, m.panelRows()-4))
	for i := lo; i < hi; i++ {
		name := groups[i].Name
		mark := "[ ]"
		if sel := selected[name]; sel > 0 {
			if sel >= total[name] {
				mark = "[✓]"
			} else {
				mark = "[~]"
			}
		}
		if m.catalogReadOnly {
			mark = ""
		}
		body.WriteString(renderListRow(fmt.Sprintf("%s  %s  (%d доступно / %d)", mark, name, groups[i].Available, groups[i].Count), i == m.catalogGroupIndex, w))
	}
	if len(groups) == 0 {
		body.WriteString(mutedStyle.Render("Ничего не найдено. Попробуй сменить группировку (1/2/3) или поиск (/)."))
	}
	if m.catalogPending {
		body.WriteString(renderListRow(fmt.Sprintf("Запустить выбранные (%d) — Enter", len(m.pendingTemplateIDs)), m.catalogGroupIndex == len(groups), w))
	}
	return m.renderPanel(w, body.String())
}

func (m model) viewCatalog(w int) string {
	var body strings.Builder
	selected := m.current.TemplateIDs
	if m.catalogReadOnly {
		selected = nil
	}
	if m.catalogPending {
		selected = m.pendingTemplateIDs
	}
	selectedIDs := make(map[string]struct{}, len(selected))
	for _, id := range selected {
		selectedIDs[id] = struct{}{}
	}
	if len(m.entries) == 0 {
		body.WriteString("Каталог пуст. Скачай шаблоны в общих настройках → Библиотека.\n")
	}
	selectedVisible := 0
	for _, entry := range m.filtered {
		if _, ok := selectedIDs[entry.Path]; ok {
			selectedVisible++
		}
	}
	if m.catalogReadOnly {
		fmt.Fprintf(&body, "%s   %d проверок\n", headingStyle.Render("Скачанные проверки"), len(m.filtered))
	} else {
		fmt.Fprintf(&body, "%s   %d проверок · %d отмечено\n", headingStyle.Render("Библиотека проверок"), len(m.filtered), selectedVisible)
	}
	if m.catalogReadOnly {
		body.WriteString(mutedStyle.Render("Скачанные проверки — просмотр") + "\n")
	} else if m.catalogPending {
		body.WriteString(m.selectionScope() + "\n")
		body.WriteString(mutedStyle.Render("Space — выбрать · Enter — запуск · ← назад\n"))
	} else {
		body.WriteString(mutedStyle.Render("Проверки проекта (используются в «Полный скан»)\n"))
		if m.librarySyncing {
			body.WriteString(mutedStyle.Render("Скачиваю библиотеку шаблонов…\n"))
		} else {
			body.WriteString(mutedStyle.Render("Скачать шаблоны: Общие настройки → Библиотека\n"))
		}
	}
	if m.catalogImpact != "" {
		fmt.Fprintf(&body, "Воздействие: %s\n", m.catalogImpact)
	}
	if m.catalogDirection != "" {
		fmt.Fprintf(&body, "Сервис: %s %s\n", m.catalogDirection, m.catalogDatabase)
	}
	if m.catalogCategory != "" {
		fmt.Fprintf(&body, "Тип: %s\n", m.catalogCategory)
	}
	if m.catalogProduct != "" {
		fmt.Fprintf(&body, "Продукт/сервис: %s\n", m.catalogProduct)
	}
	if m.search != "" {
		body.WriteString("Фильтр: " + m.search + "\n")
	}
	lo, hi := windowRange(min(m.entryIndex, max(0, len(m.filtered)-1)), len(m.filtered), max(1, m.panelRows()-5))
	for i := lo; i < hi; i++ {
		mark := "[ ]"
		if _, ok := selectedIDs[m.filtered[i].Path]; ok {
			mark = "[✓]"
		}
		entry := m.filtered[i]
		if entry.Checked && !entry.Available {
			mark = "[×]"
		}
		if m.catalogReadOnly && (!entry.Checked || entry.Available) {
			mark = ""
		}
		line := mark + "  " + entry.Path
		if isBruteEntry(entry) {
			line += " " + bruteTagStyle.Render("[БРУТ]")
		}
		body.WriteString(renderListRow(line, i == m.entryIndex, w))
	}
	if m.entryIndex < len(m.filtered) {
		e := m.filtered[m.entryIndex]
		if e.Checked && !e.Available {
			body.WriteString("Недоступно: " + truncateMid(e.Reason, max(10, w-16)) + "\n")
		}
	}
	if m.catalogPending {
		body.WriteString(renderListRow(fmt.Sprintf("Запустить выбранные (%d) — Enter", len(m.pendingTemplateIDs)), m.entryIndex == len(m.filtered), w))
	}
	return m.renderPanel(w, body.String())
}

// --- settings / history / input / repair / help ---------------------------

func (m model) viewSettings(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("Настройки проекта: "+m.current.Name) + "\n\n")
	rows := m.settingRows()
	lo, hi := windowRange(m.settingsIndex, len(rows), max(1, m.panelRows()-12))
	body.WriteString(moreLine(lo, true))
	for i := lo; i < hi; i++ {
		body.WriteString(renderListRow(rows[i], i == m.settingsIndex, w-4))
	}
	body.WriteString(moreLine(len(rows)-hi, false))
	body.WriteString("\n←/→ — переключить режим или пресет.\nEnter — ввести значение или открыть выбор.\nПрофиль запуска выставляет скорость проверок и портов,\nтаймаут и повторы разом; тонкая настройка строк выше\nпокажет «Вручную».\nЛимиты применяются к новым задачам.\nЗапущенные задачи сохраняют параметры старта.\n\nRPS — запросы в секунду для Nuclei; у Nmap это лимит\nпортовых проб, он не ограничивает весь трафик NSE.\n")
	return m.renderPanel(w, body.String())
}

func (m model) viewHistory(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("История запусков") + "\nEnter — результаты выбранного запуска · e — экспорт\n\n")
	if len(m.history) == 0 {
		body.WriteString("Запусков пока нет.\n")
	} else {
		lo, hi := windowRange(m.historyIndex, len(m.history), m.panelRows())
		body.WriteString(moreLine(lo, true))
		for i := lo; i < hi; i++ {
			r := m.history[i]
			line := fmt.Sprintf("#%-5d %-19s %-10s %s", r.ID, r.StartedAt.Local().Format("2006-01-02 15:04"), runStatusLabel(r.Status), resultCounts(groupedProjectResults(orderedResults(r.Findings))))
			body.WriteString(renderListRow(line, i == m.historyIndex, w))
		}
		body.WriteString(moreLine(len(m.history)-hi, false))
	}
	return m.renderPanel(w, body.String())
}

func (m model) viewRepair(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("Исправить адрес хоста?") + "\n\n")
	fmt.Fprintf(&body, "Сейчас: %q\nПосле:  %s\n", m.repairOld, m.repairNew)
	return m.renderPanel(w, body.String())
}

func (m model) viewInput(w int) string {
	label := map[string]string{"select-host-port": "Открытый порт: 445, 443/tcp или 53/udp", "ad-cidr": "Частная IPv4-подсеть CIDR (например 192.168.1.0/24)", "ptr-server": "IP DNS-сервера (например 10.0.0.10 или 10.0.0.10:53)", "mysql-port": "TCP-порт MySQL", "mysql-user": "Пользователь MySQL (Enter — пустое имя)", "mysql-database": "База MySQL (Enter — без выбранной базы)", "mysql-query": "SQL чтение или :rows users 100", "ssh-dict-user": "SSH-пользователь", "ssh-dict-users": "Файл пользователей (Enter — один пользователь)", "ssh-dict-passwords": "Файл словаря паролей", "ssh-dict-port": "TCP-порт SSH", "ssh-dict-rps": "SSH: попыток в секунду (0 — без ограничения скорости)", "ssh-dict-workers": "SSH: потоки 1–64", "ssh-dict-delay": "Пауза между попытками, мс: 0–60000", "web-wordlist-filter": "Поиск словаря по имени (Enter — все)", "web-discovery-url": "HTTP/HTTPS URL", "web-discovery-wordlist": "Путь к словарю (Enter — встроенный)", "web-discovery-extensions": "Расширения через запятую: php,html,txt", "web-discovery-vhost": "Virtual host (Enter — очистить)", "web-discovery-statuses": "HTTP-статусы через запятую (Enter — стандартные)", "web-discovery-sizes": "Исключить размеры ответов, байт, через запятую", "web-discovery-rps": "Запросов в секунду (0 — до 100)", "web-discovery-workers": "Параллельность: 1–64", "pg-port": "TCP-порт PostgreSQL", "pg-user": "Имя роли PostgreSQL для входа без пароля", "pg-database": "База PostgreSQL", "pg-query": "SQL только чтение или :rows public.table 100", "cred-username": "Имя пользователя", "cred-domain": "Домен (Enter — пропустить)", "cred-secret": "Пароль", "cred-notes": "Заметка (Enter — пропустить)", "lfi-url": "URL выбранного сервиса", "lfi-parameter": "Query-параметр для проверки LFI", "lfi-vhost": "Virtual host (Enter — очистить)", "kyocera-port": "TCP-порт сервиса Kyocera (обычно 9091)", "kyocera-wait": "Пауза перед запросом книги, сек (0–60)", "ftp-port": "TCP-порт FTP-сервера", "ftp-path": "Путь FTP-каталога", "smb-port": "TCP-порт выбранного SMB-сервиса", "module-share": "Имя SMB-шары для поиска конфигураций", "mssql-nse": "NSE: ms-sql-info / ms-sql-hasdbaccess / ms-sql-tables", "mssql-port": "TCP-порт MSSQL", "mssql-columns": "Таблица (schema.table)", "mssql-rows": "Таблица и число строк (dbo.users 100; максимум 500)", "mssql-count": "Таблица (schema.table)", "mssql-transfer-local": "Локальный файл для передачи", "mssql-transfer-address": "Наш IP, доступный Windows (VPN/IP интерфейса)", "mssql-transfer-port": "Порт Python HTTP-сервера", "mssql-transfer-remote": "Путь назначения на Windows (%TEMP%\\winPEAS.exe)", "mssql-winpeas": "Путь WinPEAS.exe на Windows", "mssql-report": "Путь текстового отчёта на Windows", "mssql-command": "Команда ОС через xp_cmdshell", "mssql-query": "SQL-запрос (может менять данные и настройки)", "mssql-database": "Имя базы MSSQL", "winrm-port": "TCP-порт WinRM", "winrm-path": "Каталог Windows (например C:\\Users)", "winrm-shell-command": "Команда в PowerShell-сессии", "winrm-command": "Одна команда PowerShell", "bulk-port": "Один порт на выбранных хостах (445, 443/tcp, 53/udp)", "new-project": "Название проекта", "add-target": "IP, имя хоста или URL", "add-network": "Подсеть CIDR (например 10.0.0.0/24)", "project-results-search": "Поиск результатов: хост, порт, CVE, название или текст", "search": "Фильтр шаблонов", "disc-ports": "Порты (напр. 22,80,443,8000-8100)"}[m.inputAction]
	if label == "" {
		label = map[string]string{"ad-bloodhound-limit": "BloodHound: лимит объектов и членов одной группы (1–50000)", "ad-access-host": "Хост контроллера домена (IP/DNS)", "ad-access-domain": "DNS-имя домена", "ad-coerce-callback": "Локальный IPv4 приёмника, доступный машинам (например адрес VPN)"}[m.inputAction]
	}
	if m.inputAction == "setting-value" {
		label = settingLabels[m.settingsIndex]
	}
	if m.inputAction == "disc-setting-value" {
		label = "Проб/сек (0 — без лимита)"
		if m.discOptIndex == 7 {
			label = "Параллельность поиска портов (1–2048)"
		}
	}
	if m.inputAction == "scan-setting-value" {
		label = settingLabels[m.scanReviewIndex-1]
	}
	value := m.input
	if m.inputAction == "cred-secret" {
		if m.credNewType == "ntlm-hash" {
			label = "NTLM-хеш"
		}
	}
	body := fmt.Sprintf("%s: %s▏\n", label, value)
	return m.renderPanel(w, body)
}

func (m model) panelStyle(w int) lipgloss.Style {
	return lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(idleBorder).Padding(0, 1).Width(max(1, w-2))
}

// renderPanel sizes the panel body to exactly fill the body area: content is
// padded/truncated to bodyHeight-2, then a border is drawn around it so the
// bottom edge always sits above the activity/footer chrome.
func (m model) renderPanel(w int, body string) string {
	switch m.screen {
	case "input", "action-menu", "disc-options", "delete-confirm", "repair-target":
		outerW := dialogWidth(m.screen, w)
		innerW := max(1, outerW-4)
		body = wrapPaneBody(body, innerW)
		contentH := min(max(1, m.bodyHeight()-2), max(3, lipgloss.Height(body)))
		panel := m.panelStyle(outerW).Render(fitContent(body, innerW, contentH))
		return lipgloss.Place(w, m.bodyHeight(), lipgloss.Center, lipgloss.Center, panel)
	}
	contentH := max(1, m.bodyHeight()-2)
	innerW := max(1, w-4) // Width(w-2) minus horizontal padding
	return m.panelStyle(w).Render(fitContent(wrapPaneBody(body, innerW), innerW, contentH))
}

// panelRows is how many list rows fit in a single-panel screen, leaving room
// for the header, panel border, heading, message and footer chrome.
func (m model) panelRows() int {
	if m.height <= 0 {
		return 15
	}
	return max(1, m.bodyHeight()-7)
}
