package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/catalog"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

// actionRow is one selectable line in the action menu opened with Enter.
type actionRow struct {
	title       string
	kind        string
	needsPicker bool
}

func (m model) actionRows() []actionRow {
	if m.actionService != nil {
		return []actionRow{
			{title: "Проверки на этом порту…", kind: jobPort, needsPicker: true},
			{title: "Взаимодействие…", kind: "interaction"},
		}
	}
	if hasNetworkTarget(m.actionHosts) {
		return []actionRow{
			{title: "Найти живые хосты (ARP / ICMP / TCP)", kind: jobAlive},
			{title: "Сканировать порты найденных хостов…", kind: jobDiscover},
			{title: "Найти имена по PTR через DNS-сервер…", kind: jobPTR},
		}
	}
	rows := []actionRow{
		{title: "Проверить найденные сервисы…", kind: jobChecks, needsPicker: true},
		{title: "Найти порты и определить сервисы…", kind: jobDiscover},
		{title: "Полный скан (discovery + проверки проекта)", kind: jobFull},
		{title: "Проверить один порт на выбранных хостах…", kind: jobBulkPort},
		{title: "Взаимодействие…", kind: "interaction"},
	}
	return rows
}

// Update is the single keyboard router for wscan's desk-based workflow.
// Scans never block it: they run as background jobs (see jobs.go) and only
// a jobEvent message flows back in.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch x := msg.(type) {
	case findingCommandCopied:
		m.message = "Команда отправлена в буфер терминала (OSC 52)."
		if x.err != nil {
			m.message = "Копирование команды: " + x.err.Error()
		}
		return m, nil
	case adAccessIdentityDetected:
		m.applyADAccessIdentity(x)
		return m, nil
	case webBrowserOpened:
		m.message = webOpenMessage(x.err)
		return m, nil
	case coercePortChecked:
		return m.applyCoercionPortChecked(x)
	case coercePortReleased:
		return m.applyCoercionPortReleased(x)
	case coercePortRestored:
		if x.err != nil {
			m.message = "Восстановление Samba: " + x.err.Error()
		}
		return m, nil
	case resultDeleted:
		return m.applyResultDeleted(x)
	case coerceRouteReady:
		return m.applyCoerceRoute(x)
	case sshDictionaryProgress:
		return m.applySSHDictionaryProgress(x)
	case sshDictionaryDone:
		return m.applySSHDictionaryDone(x)
	case sshDictionaryClosed:
		return m, nil
	case webDiscoveryDelivery:
		return m.applyWebDiscoveryEvent(x.event, x.channel)
	case webDiscoveryDone:
		return m.applyWebDiscoveryDone(x)
	case webDiscoveryClosed:
		return m, nil
	case sqliFormDelivery:
		return m.applySQLiFormEvent(x.event, x.channel)
	case sqliFormDone:
		return m.applySQLiFormDone(x)
	case sqliFormClosed:
		return m, nil
	case fileUploadDelivery:
		return m.applyFileUploadEvent(x.event, x.channel)
	case fileUploadDone:
		return m.applyFileUploadDone(x)
	case fileUploadClosed:
		return m, nil
	case ftpDone:
		return m.applyFTPDone(x)
	case ftpDownloadTick:
		if x.generation == m.ftpBrowser.generation && m.ftpBrowser.busy && m.ftpBrowser.download != nil && m.screen == "ftp-browser" {
			return m, tickFTPDownload(x.generation)
		}
		return m, nil
	case smbAuthDone:
		return m.applySMBAuthDone(x)
	case lfiDone:
		return m.applyLFIDone(x)
	case kyoceraDone:
		return m.applyKyoceraDone(x)
	case mysqlDone:
		return m.applyMySQLDone(x)
	case pgDone:
		return m.applyPGDone(x)
	case mssqlDone:
		return m.applyMSSQLDone(x)
	case winRMDone:
		return m.applyWinRMDone(x)
	case smbDownloadTick:
		return m.applySMBDownloadTick(x)
	case smbBrowserDone:
		return m.applySMBBrowserDone(x)
	case jobTick:
		m.syncSharedJobs()
		dnsCmd := m.resolveHostNamesCmd()
		return m, tea.Batch(tickJobs(), dnsCmd)
	case hostNamesDone:
		m.dnsBusy = false
		if m.store != nil {
			if err := m.store.SaveHostNames(m.ctx, x.projectID, x.names); err != nil {
				m.message = "Не удалось сохранить DNS-имена: " + err.Error()
			}
		}
		if x.projectID == m.current.ID {
			if m.hostNames == nil {
				m.hostNames = make(map[string][]string)
			}
			if m.dnsChecked == nil {
				m.dnsChecked = make(map[string]time.Time)
			}
			for host, names := range x.names {
				if m.dnsPinned[host] {
					continue
				}
				m.hostNames[host] = names
				m.dnsChecked[host] = time.Now()
			}
		}
		dnsCmd := m.resolveHostNamesCmd()
		return m, dnsCmd
	case tea.WindowSizeMsg:
		m.width, m.height = x.Width, x.Height
		return m, nil

	case jobEvent:
		m.applyJobEvent(x)
		return m, waitForJob(m.jobEvents)

	case sprayDone:
		m.sprayResults = x.results
		m.sprayResultIndex = 0
		if x.err != nil {
			m.message = "Ошибка credential-атаки: " + x.err.Error()
		}
		m.screen = "spray-results"
		return m, nil

	case moduleDone:
		m.sprayModuleResult = x.result
		if x.err != nil && x.result == nil {
			m.message = "Ошибка модуля: " + x.err.Error()
			m.screen = "spray-results"
			return m, nil
		}
		m.screen = "spray-module-result"
		return m, nil

	case syncDone:
		if x.err != nil {
			m.catalogLoadError = "Не удалось загрузить каталог: " + x.err.Error()
			m.message = m.catalogLoadError
		} else {
			m.catalogLoadError = ""
			m.entries = x.entries
			m.enrichFinding()
			m.applyFilter()
			if m.catalogPending && m.actionService != nil && m.catalogAxis == "direction" {
				for i, g := range m.visibleCatalogGroups() {
					if g.Name == catalog.ServiceDirection(*m.actionService) {
						m.catalogGroupIndex = i
						break
					}
				}
			}
			m.message = fmt.Sprintf("Каталог обновлён: %d шаблонов", len(x.entries))
		}
		return m, nil

	case dependenciesDone:
		m.dependenciesLoading = false
		changed := false
		if len(m.interpreters) == len(x.items) {
			for i := range x.items {
				if m.interpreters[i].Installed() != x.items[i].Installed() {
					changed = true
				}
			}
		}
		m.interpreters = x.items
		if changed {
			return m, m.loadCatalogCmd()
		}
		return m, nil
	case dependencyInstallDone:
		if x.err != nil {
			m.dependencyError = "Установка не завершена: " + x.err.Error()
		} else {
			m.dependencyError = ""
			m.message = "Установка завершена; проверяю интерпретаторы"
			if x.browser {
				m.message = "Страница установки открыта. После установки нажмите r."
			}
		}
		return m, m.inspectDependenciesCmd()
	case libraryStatusDone:
		m.libraryStatusLoading = false
		m.libraryStatus = x.status
		if x.err != nil {
			m.libraryError = x.err.Error()
		}
		return m, nil
	case libraryUpdateDone:
		m.librarySyncing = false
		if x.err != nil {
			m.libraryError = x.err.Error()
			m.message = "Не удалось скачать библиотеку шаблонов: " + x.err.Error()
			return m, nil
		}
		m.cat = catalog.NewWithLibrary(filepath.Join(m.appDir, "templates"), x.cfg.Path)
		m.libraryError = ""
		m.scanner = engine.New(m.store, engine.Config{RPS: 5, Concurrency: 4, TimeoutSeconds: 10, Complete: false, OAST: true, LibraryDir: x.cfg.Path})
		m.message = "Библиотека шаблонов скачана или обновлена"
		return m, tea.Batch(m.loadCatalogCmd(), m.inspectLibraryCmd())

	case templateDone:
		if x.err != nil {
			m.message = x.err.Error()
			return m, nil
		}
		if m.catalogPending {
			m.toggleScanTemplate(x.entry.Path)
			m.message = "Для этого действия: " + x.entry.Path
		} else {
			if err := m.store.ToggleTemplate(m.ctx, m.current.ID, x.entry.Path); err != nil {
				m.message = err.Error()
			} else {
				_ = m.reload()
				m.current = m.findProject(m.current.ID)
				m.message = "Шаблон обновлён: " + x.entry.Path
			}
		}
		return m, nil

	case bulkTemplatesDone:
		if x.err != nil {
			m.message = "Не удалось изменить выбор: " + x.err.Error()
			return m, nil
		}
		if m.catalogPending {
			m.setScanTemplateSelection(x.ids, x.selected)
		} else {
			_ = m.reload()
			m.current = m.findProject(m.current.ID)
		}
		verb := "снято"
		if x.selected {
			verb = "выбрано"
		}
		m.message = fmt.Sprintf("%d проверок %s", x.count, verb)
		return m, nil

	case tea.KeyMsg:
		if m.screen == "input" {
			return m.updateInput(x)
		}
		if x.String() == "ctrl+c" {
			m.closeMSSQL()
			m.closePG()
			m.closeMySQL()
			if m.sshDictionary.cancel != nil {
				m.sshDictionary.cancel()
			}
			if m.webDiscovery.cancel != nil {
				m.webDiscovery.cancel()
			}
			if m.ftpBrowser.cancel != nil {
				m.ftpBrowser.cancel()
			}
			if m.lfiAudit.cancel != nil {
				m.lfiAudit.cancel()
			}
			if m.kyoceraBook.cancel != nil {
				m.kyoceraBook.cancel()
			}
			shell := m.winrmBrowser.shell
			m.closeWinRMShell()
			if shell != nil {
				return m, func() tea.Msg {
					ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
					defer cancel()
					shell.CloseAndWait(ctx)
					return tea.Quit()
				}
			}
			return m, tea.Quit
		}
		key := x.String()
		if m.screen != "service-inventory" || !m.serviceInventoryEditing {
			key = normalizeShortcut(key)
		}
		if m.screen == "web-connect" {
			return m.updateWebConnect(key)
		}
		if key == "w" && m.webURL != "" && (m.screen == "projects" || m.screen == "overview" || m.screen == "recon") {
			m.screen = "web-connect"
			return m, nil
		}
		if m.screen == "project-results" && m.resultDeleteConfirm {
			return m.confirmResultDelete(key)
		}
		if next, cmd, ok := m.selectSidebarShortcut(key); ok {
			return next, cmd
		}
		if m.hasSidebar() && m.screen != "recon" {
			if next, cmd, ok := m.updateSidebar(key); ok {
				return next, cmd
			}
		}
		if next, ok := m.navigateWorkspace(key); ok {
			return next, nil
		}

		if key == "g" && m.screen != "jobs" && !(m.screen == "service-inventory" && m.serviceInventoryEditing) {
			m.jobsReturn = m.screen
			m.jobIndex = max(0, len(m.jobs)-1)
			m.screen = "jobs"
			return m, nil
		}

		if m.screen == "repair-target" {
			switch key {
			case "enter", "y":
				if err := m.store.ReplaceTarget(m.ctx, m.current.ID, m.repairOld, m.repairNew); err != nil {
					m.message = "Не удалось заменить адрес: " + err.Error()
				} else {
					_ = m.reload()
					m.current = m.findProject(m.current.ID)
					m.rebuildHostOrder()
					m.selectHost(m.repairNew)
					m.message = "Адрес исправлен: " + m.repairNew
				}
				m.screen = "desk"
			case "esc":
				m.screen = "desk"
			}
			return m, nil
		}

		if key == "?" && !(m.screen == "service-inventory" && m.serviceInventoryEditing) {
			if m.screen == "help" {
				m.screen = m.helpReturn
			} else {
				m.helpReturn, m.screen = m.screen, "help"
				m.helpOffset = 0
			}
			return m, nil
		}
		if m.screen == "help" {
			return m.updateHelp(key)
		}

		switch m.screen {
		case "ssh-password-lists":
			return m.updateSSHPasswordLists(key)
		case "ssh-dictionary":
			return m.updateSSHDictionary(key)
		case "web-wordlists":
			return m.updateWebWordlists(key)
		case "web-discovery":
			return m.updateWebDiscovery(key)
		case "sqli-form":
			return m.updateSQLiForm(key)
		case "file-upload":
			return m.updateFileUpload(key)
		case "interaction-targets":
			return m.updateInteractionTargets(key)
		case "ftp-setup":
			return m.updateFTPSetup(key)
		case "ftp-browser":
			return m.updateFTPBrowser(key)
		case "smb-setup":
			return m.updateSMBCredentials(key)
		case "lfi-audit":
			return m.updateLFI(key)
		case "kyocera-book":
			return m.updateKyocera(key)
		case "mysql-setup", "mysql-console":
			return m.updateMySQL(key)
		case "pg-setup", "pg-console":
			return m.updatePG(key)
		case "mssql-setup", "mssql-console", "mssql-actions", "mssql-xp-confirm":
			return m.updateMSSQL(key)
		case "winrm-shell":
			return m.updateWinRMShell(key)
		case "winrm-setup":
			return m.updateWinRMSetup(key)
		case "winrm-browser":
			return m.updateWinRMBrowser(key)
		case "interaction-menu":
			return m.updateInteractionMenu(key)
		case "smb-browser":
			return m.updateSMBBrowser(key)
		case "project-delete-confirm":
			return m.updateProjectDelete(key)
		case "checks-menu":
			return m.updateChecksMenu(key)
		case "ad-menu":
			return m.updateADMenu(key)
		case "recon-host-menu":
			return m.updateReconHostMenu(key)
		case "recon":
			return m.updateRecon(key)
		case "overview":
			return m.updateOverview(key)
		case "guided-scan":
			return m.updateGuidedScan(key)
		case "projects":
			return m.updateProjects(key)
		case "ad-scan":
			return m.updateADScan(key)
		case "coerce-port-check", "coerce-port-confirm", "coerce-port-stopping":
			return m.updateCoercionPort(key)
		case "coerce-setup":
			return m.updateCoercionSetup(key)
		case "ad-access":
			return m.updateADAccess(key)
		case "asrep-setup":
			return m.updateASREPSetup(key)
		case "ad-controller-picker":
			return m.updateADControllerPicker(key)
		case "host-port-selection":
			return m.updateHostPortSelection(key)
		case "host-selection":
			return m.updateHostSelection(key)
		case "desk":
			return m.updateDesk(key)
		case "service-inventory":
			return m.updateServiceInventory(key)
		case "port-browser":
			return m.updatePortBrowser(key)
		case "networks":
			return m.updateNetworks(key)
		case "action-menu":
			return m.updateActionMenu(key)
		case "disc-options":
			return m.updateDiscOptions(key)
		case "jobs":
			return m.updateJobs(key)
		case "job-details":
			return m.updateJobDetails(key)
		case "project-results":
			return m.updateProjectResults(key)
		case "finding-details":
			return m.updateFindingDetails(key)
		case "scan-review":
			return m.updateScanReview(key)
		case "catalog-groups":
			return m.updateCatalogGroups(key)
		case "catalog":
			return m.updateCatalog(key)
		case "dependency-settings":
			return m.updateDependencySettings(key)
		case "dependency-install-confirm":
			return m.updateDependencyInstallConfirm(key)
		case "library-settings":
			return m.updateLibrarySettings(key)
		case "global-settings":
			return m.updateGlobalSettings(key)
		case "settings":
			return m.updateSettings(key)
		case "speed-presets":
			return m.updateSpeedPresets(key)
		case "delete-confirm":
			return m.updateDelete(key)
		case "code-exec-confirm":
			return m.updateCodeExecConfirm(key)
		case "exploit-confirm":
			return m.updateExploitConfirm(key)
		case "credential-attack-confirm":
			return m.updateCredentialAttackConfirm(key)
		case "credentials":
			return m.updateCredentials(key)
		case "cred-add-type":
			return m.updateCredAddType(key)
		case "cred-delete-confirm":
			return m.updateCredDeleteConfirm(key)
		case "spray-setup":
			return m.updateSpraySetup(key)
		case "spray-results":
			return m.updateSprayResults(key)
		case "spray-module-picker":
			return m.updateSprayModulePicker(key)
		case "spray-module-result":
			return m.updateSprayModuleResult(key)
		case "history":
			return m.updateHistory(key)
		}
	}
	return m, nil
}

func (m model) updateProjects(key string) (tea.Model, tea.Cmd) {
	m.catalogReadOnly = false
	switch key {
	case "p":
		m.screen = "global-settings"
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
	case "down", "j":
		if m.selected+1 < len(m.projects) {
			m.selected++
		}
	case "delete", "backspace", "D":
		m.requestProjectDelete()
	case "n", "a":
		m.startInput("new-project")
	case "d":
		m.openADScan()
		return m, nil
	case "enter":
		if len(m.projects) > 0 {
			m.openProject(m.projects[m.selected])
		}
	case "q", "esc":
		return m, tea.Quit
	}
	return m, nil
}

// --- desk ------------------------------------------------------------

func (m model) updateDesk(key string) (tea.Model, tea.Cmd) {
	if key == "m" {
		return m.openDeskCommand()
	}
	if key == "esc" {
		if m.sidebarEnabled {
			m.reconMenuFocus = true
			return m, nil
		}
		m.openHostScope("")
		m.screen = "recon"
		return m, nil
	}
	if key == "f" {
		m.actionIndex = 0
		m.screen = "host-selection"
		return m, nil
	}
	if key == "i" {
		m.openInteractionMenu()
		return m, nil
	}
	if key == "v" {
		m.serviceInventoryIndex = 0
		m.serviceInventoryProject = false
		m.serviceInventoryEditing = false
		m.serviceInventorySelected = nil
		m.screen = "service-inventory"
		m.message = ""
		return m, nil
	}
	services := m.servicesFor(m.currentHost())
	switch key {
	case "esc", "q":
		m.screen = "projects"
		m.message = ""
		return m, nil
	case "tab":
		m.focusCol = (m.focusCol + 1) % 3
		return m, nil
	case "shift+tab":
		m.focusCol = (m.focusCol + 2) % 3
		return m, nil
	case "right":
		// Drill rightwards: hosts → ports → details.
		if m.focusCol < 2 {
			m.focusCol++
			if m.focusCol == 1 && m.serviceIndex >= len(services) {
				m.serviceIndex = len(services) - 1
			}
		}
		return m, nil
	case "left":
		// Step back leftwards: details → ports → hosts.
		if m.focusCol > 0 {
			m.focusCol--
		}
		return m, nil
	case "up", "k":
		switch m.focusCol {
		case 0:
			if len(m.hostOrder) > 0 {
				if m.preferredPort == 0 {
					m.rememberSelectedPort(services)
				}
				if m.hostIndex < 0 {
					m.hostIndex = len(m.hostOrder) - 1
				} else {
					m.hostIndex--
				}
				m.restoreSelectedPort()
				m.findingIndex = 0
			}
		case 1:
			if m.serviceIndex > -1 {
				m.serviceIndex--
				m.rememberSelectedPort(services)
				m.findingIndex = 0
			}
		case 2:
			if m.findingIndex > 0 {
				m.findingIndex--
			}
		}
	case "down", "j":
		switch m.focusCol {
		case 0:
			if len(m.hostOrder) > 0 {
				if m.preferredPort == 0 {
					m.rememberSelectedPort(services)
				}
				if m.hostIndex+1 >= len(m.hostOrder) {
					m.hostIndex = -1
				} else {
					m.hostIndex++
				}
				m.restoreSelectedPort()
				m.findingIndex = 0
			}
		case 1:
			if m.serviceIndex < 0 && len(services) > 0 {
				m.serviceIndex = 0
				m.rememberSelectedPort(services)
				m.findingIndex = 0
			} else if m.serviceIndex+1 < len(services) {
				m.serviceIndex++
				m.rememberSelectedPort(services)
				m.findingIndex = 0
			}
		case 2:
			if m.hostIndex >= 0 {
				fs := m.deskFindings()
				if m.findingIndex+1 < len(fs) {
					m.findingIndex++
				}
			}
		}
	case "enter":
		if m.focusCol == 2 && m.openFinding() {
			return m, nil
		}
		m.openActionMenu(services)
	case "s":
		m.openActionMenu(services)
	case " ", "space":
		if m.focusCol == 0 && m.hostIndex == -1 {
			m.actionIndex = 0
			m.screen = "host-selection"
		} else if m.focusCol == 0 && m.hostIndex >= 0 {
			host := m.currentHost()
			if m.selectedHosts == nil {
				m.selectedHosts = map[string]bool{}
			}
			m.selectedHosts[host] = !m.selectedHosts[host]
			if !m.selectedHosts[host] {
				delete(m.selectedHosts, host)
			}
			m.message = fmt.Sprintf("Выбрано хостов: %d · Enter — действие для выбранных", len(m.selectedHosts))
		}
	case "a":
		m.startInput("add-target")
	case "w":
		m.networkIndex = 0
		m.screen = "networks"
		m.message = "Выбери подсеть или добавь диапазон клавишей a."
	case "r":
		m.repairSelectedHost()
	case "d", "delete":
		m.requestDelete()
	case "t":
		m.pendingTemplateIDs = nil
		m.openCatalog(false, "desk")
	case ",":
		m.screen = "settings"
	case "c":
		m.openCredentials()
	case "x":
		if m.serviceIndex >= 0 && m.serviceIndex < len(services) {
			m.openSpraySetup(services[m.serviceIndex])
		} else {
			m.message = "Выбери конкретный порт для credential-атаки."
		}
	case "h":
		m.history, _ = m.store.Runs(m.ctx, m.current.ID)
		m.historyIndex = 0
		m.screen = "history"
	case "e":
		if len(m.history) > 0 {
			if err := m.export(m.history[0]); err != nil {
				m.message = err.Error()
			} else {
				m.message = "Отчёты сохранены в reports/"
			}
		} else {
			m.message = "Пока нет ни одного завершённого запуска"
		}
	}
	return m, nil
}

// updateNetworks handles the dedicated CIDR inventory window.
func (m model) updateNetworks(key string) (tea.Model, tea.Cmd) {
	networks := m.networkTargets()
	switch key {
	case "esc", "q", "h":
		m.openHostScope("")
		m.message = ""
	case "o", "right":
		if m.networkIndex >= 0 && m.networkIndex < len(networks) {
			m.openHostScope(networks[m.networkIndex])
			m.message = ""
		}
	case "up", "k":
		if m.networkIndex > 0 {
			m.networkIndex--
		}
	case "down", "j":
		if m.networkIndex+1 < len(networks) {
			m.networkIndex++
		}
	case "a":
		m.startInput("add-network")
	case " ", "space":
		if m.networkIndex >= 0 && m.networkIndex < len(networks) {
			if m.selectedNetworks == nil {
				m.selectedNetworks = map[string]bool{}
			}
			network := networks[m.networkIndex]
			m.selectedNetworks[network] = !m.selectedNetworks[network]
			if !m.selectedNetworks[network] {
				delete(m.selectedNetworks, network)
			}
		}
	case "enter":
		var chosen []string
		for _, network := range networks {
			if m.selectedNetworks[network] {
				chosen = append(chosen, network)
			}
		}
		if len(chosen) == 0 && m.networkIndex >= 0 && m.networkIndex < len(networks) {
			chosen = []string{networks[m.networkIndex]}
		}
		if len(chosen) == 0 {
			m.message = "Добавь подсеть клавишей a."
			return m, nil
		}
		m.actionHosts = chosen
		m.actionService = nil
		m.actionIndex = 0
		m.actionReturn = "networks"
		m.pendingTemplateIDs = nil
		m.screen = "action-menu"
	case "d", "delete":
		if m.networkIndex >= 0 && m.networkIndex < len(networks) {
			m.deleteNetwork = networks[m.networkIndex]
			m.screen = "delete-confirm"
		}
	}
	return m, nil
}

func (m *model) openActionMenu(services []domain.Service) {
	m.pendingTemplateIDs = nil
	m.bulkPort, m.bulkProtocol = 0, ""
	m.actionIndex = 0
	if m.focusCol >= 1 && m.hostIndex >= 0 && m.serviceIndex >= 0 && m.serviceIndex < len(services) {
		svc := services[m.serviceIndex]
		m.actionService = &svc
		// actionHosts still carries the desk's bucket name (not svc.Host, which
		// is the resolved dial address) so jobs/history can jump back to the
		// right row even for domain targets.
		m.actionHosts = []string{m.currentHost()}
	} else {
		// Host scope: the hosts column, "All hosts", or the "All ports" row at
		// the top of the services column (serviceIndex == -1).
		m.actionService = nil
		if len(m.selectedTargetHosts()) > 0 {
			m.actionHosts = m.selectedTargetHosts()
		} else if m.hostIndex >= 0 {
			m.actionHosts = []string{m.currentHost()}
		} else {
			// "All hosts": use normalized bucket names so inventory lookups
			// (known services / web targets) match.
			m.actionHosts = m.targetBuckets()
		}
	}
	m.screen = "action-menu"
	m.actionReturn = "desk"
	m.message = ""
	if m.actionService == nil && len(m.knownServices(m.actionHosts)) == 0 && !hasNetworkTarget(m.actionHosts) {
		m.actionIndex = 1
	}
}

func hasNetworkTarget(hosts []string) bool {
	for _, host := range hosts {
		if discovery.IsNetworkTarget(host) {
			return true
		}
	}
	return false
}

func (m *model) repairSelectedHost() {
	host := m.currentHost()
	if host == "" {
		m.message = "Выбери хост стрелками"
		return
	}
	found := ""
	for _, t := range m.current.Targets {
		if t == host {
			found = t
			break
		}
	}
	if found == "" {
		m.message = "Это обнаруженный адрес, а не добавленная цель — исправлять нечего"
		return
	}
	if utf8.ValidString(found) {
		m.message = "Адрес уже корректный"
		return
	}
	m.repairOld = found
	m.repairNew = strings.ToValidUTF8(found, "")
	if _, err := discovery.TargetHost(m.repairNew); err != nil {
		m.message = "Адрес не удалось восстановить: " + err.Error()
		return
	}
	m.screen = "repair-target"
}

func (m *model) removeSelectedHost() {
	host := m.currentHost()
	if host == "" {
		m.message = "Выбери хост стрелками"
		return
	}
	found := false
	for _, t := range m.current.Targets {
		if t == host {
			found = true
			break
		}
	}
	if !found {
		m.message = "Это обнаруженный адрес, а не добавленная цель — удалять нечего"
		return
	}
	if err := m.store.RemoveTarget(m.ctx, m.current.ID, host); err != nil {
		m.message = err.Error()
		return
	}
	_ = m.reload()
	m.current = m.findProject(m.current.ID)
	delete(m.inventory, host)
	m.rebuildHostOrder()
	if m.hostIndex >= len(m.hostOrder) {
		m.hostIndex = len(m.hostOrder) - 1
	}
	m.message = "Хост удалён: " + host
}

// --- action menu -------------------------------------------------------

func (m model) updateActionMenu(key string) (tea.Model, tea.Cmd) {
	rows := m.actionRows()
	switch key {
	case "esc":
		m.screen = m.actionReturn
		if m.screen == "" {
			m.screen = "desk"
		}
		m.pendingTemplateIDs = nil
	case "up", "k":
		if m.actionIndex > 0 {
			m.actionIndex--
		}
	case "down", "j":
		if m.actionIndex+1 < len(rows) {
			m.actionIndex++
		}
	case " ", "space":
		row := rows[m.actionIndex]
		if row.needsPicker {
			m.bulkPort, m.bulkProtocol = 0, ""
			m.openCatalog(true, "action-menu")
		}
	case "enter":
		row := rows[m.actionIndex]
		if row.kind == jobPTR {
			m.startInput("ptr-server")
			return m, nil
		}
		if row.kind == jobBulkPort {
			m.actionService = nil
			m.startInput("bulk-port")
			m.input = "445"
			if m.bulkPort > 0 {
				m.input = fmt.Sprintf("%d/%s", m.bulkPort, m.bulkProtocol)
			}
			return m, nil
		}
		m.bulkPort, m.bulkProtocol = 0, ""
		if row.kind == "interaction" {
			m.openInteractionMenu()
			return m, nil
		}
		if row.kind == jobDiscover {
			m.openDiscOptions()
			return m, nil
		}
		if row.kind == jobAlive {
			spec, err := m.buildSpec(row)
			if err != "" {
				m.message = err
				return m, nil
			}
			m.startLaunch(spec)
			if len(spec.hosts) == 1 {
				m.openHostScope(spec.hosts[0])
			} else {
				m.openHostScope("")
			}
			m.message = "Запущено: " + spec.label
			return m, nil
		}
		if row.needsPicker && len(m.pendingTemplateIDs) == 0 {
			m.openCatalog(true, "action-menu")
			return m, nil
		}
		spec, err := m.buildSpec(row)
		if err != "" {
			m.message = err
			return m, nil
		}
		m.startLaunch(spec)
		m.pendingTemplateIDs = nil
		m.screen = "desk"
		m.message = "Запущено: " + spec.label
	}
	return m, nil
}

func (m model) buildSpec(row actionRow) (launchSpec, string) {
	switch row.kind {
	case jobBulkPort:
		services, hosts := m.bulkPortServices()
		if len(services) == 0 {
			return launchSpec{}, "Нет хостов с выбранным открытым портом"
		}
		if len(m.pendingTemplateIDs) == 0 {
			return launchSpec{}, "Не выбрано ни одной проверки"
		}
		return launchSpec{kind: jobBulkPort, label: fmt.Sprintf("Порт %d/%s на %d хостах", m.bulkPort, m.bulkProtocol, len(hosts)), hosts: hosts, templateIDs: append([]string(nil), m.pendingTemplateIDs...), services: services, port: m.bulkPort, protocol: m.bulkProtocol}, ""
	case jobDiscover:
		return launchSpec{kind: jobDiscover, label: "Discover: " + strings.Join(m.actionHosts, ", "), hosts: m.actionHosts}, ""
	case jobAlive:
		return launchSpec{kind: jobAlive, label: "Живые хосты: " + strings.Join(m.actionHosts, ", "), hosts: m.actionHosts}, ""
	case jobChecks:
		ids := append([]string(nil), m.pendingTemplateIDs...)
		if len(ids) == 0 {
			return launchSpec{}, "Не выбрано ни одной проверки"
		}
		return launchSpec{kind: jobChecks, label: fmt.Sprintf("Проверки (%d) на %s", len(ids), strings.Join(m.actionHosts, ", ")), hosts: m.actionHosts, templateIDs: ids}, ""
	case jobFull:
		if len(m.current.TemplateIDs) == 0 {
			return launchSpec{}, "Библиотека проекта пуста — открой 't' на столе и выбери проверки"
		}
		return launchSpec{kind: jobFull, label: "Полный скан: " + strings.Join(m.actionHosts, ", "), hosts: m.actionHosts}, ""
	case jobPort:
		ids := append([]string(nil), m.pendingTemplateIDs...)
		if len(ids) == 0 {
			return launchSpec{}, "Не выбрано ни одной проверки"
		}
		svc := m.actionService
		hosts := m.actionHosts
		if len(hosts) == 0 {
			hosts = []string{svc.Host}
		}
		return launchSpec{kind: jobPort, label: fmt.Sprintf("Проверки %s:%d", svc.Host, svc.Port), hosts: hosts, templateIDs: ids, service: svc}, ""
	}
	return launchSpec{}, "неизвестное действие"
}

func (m *model) openDiscOptions() {
	m.discReturn = m.screen
	m.discProject = m.current
	m.discOnlyKnown = false
	m.discHosts = append([]string(nil), m.actionHosts...)
	m.discOptIndex = 0
	m.discSetIndex = 3
	m.discTCP = true
	m.discUDP = false
	m.discVersion = true
	m.discNoPing = !hasNetworkTarget(m.discHosts)
	m.screen = "disc-options"
	m.message = ""
}

func (m model) updateDiscOptions(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "left", "right":
		switch m.discOptIndex {
		case 8:
			m.discOnlyKnown = !m.discOnlyKnown
		case 9:
			m.discNoPing = !m.discNoPing
		case 0:
			delta := 1
			if key == "left" {
				delta = -1
			}
			m.discSetIndex = (m.discSetIndex + delta + len(discSetLabels)) % len(discSetLabels)
		case 1:
			m.discTCP = !m.discTCP
		case 2:
			m.discUDP = !m.discUDP
		case 3:
			m.discVersion = !m.discVersion
		case 5:
			m.discProject = cycleSpeed(m.discProject, true, key)
		}
	case "home", "end":
		m.discOptIndex = 4
	case "esc":
		m.screen = m.discReturn
		if m.screen == "" {
			m.screen = "action-menu"
		}
	case "up", "k":
		if m.discOptIndex > 0 {
			m.discOptIndex--
		}
	case "down", "j":
		if m.discOptIndex < 10 {
			m.discOptIndex++
		}
	case " ", "space":
		switch m.discOptIndex {
		case 8:
			m.discOnlyKnown = !m.discOnlyKnown
		case 9:
			m.discNoPing = !m.discNoPing
		case 0:
			m.discSetIndex = (m.discSetIndex + 1) % 5
		case 1:
			m.discTCP = !m.discTCP
		case 2:
			m.discUDP = !m.discUDP
		case 3:
			m.discVersion = !m.discVersion
		case 5:
			m.discProject = cycleSpeed(m.discProject, true, "right")
		}
	case "e":
		if m.discOptIndex == 0 {
			m.discSetIndex = 4
			m.startInput("disc-ports")
			return m, nil
		}
		if m.discOptIndex == 6 || m.discOptIndex == 7 {
			m.startInput("disc-setting-value")
			value := m.discProject.DiscoveryRPS
			if m.discOptIndex == 7 {
				value = m.discProject.DiscoveryConcurrency
			}
			m.input = fmt.Sprint(value)
			return m, nil
		}
	case "enter":
		if m.discOptIndex == 10 {
			return m.updateDiscOptions("esc")
		}
		spec, errMsg := m.buildDiscoverSpec()
		if errMsg != "" {
			m.message = errMsg
			return m, nil
		}
		m.startLaunch(spec)
		if len(spec.hosts) == 1 && hasNetworkTarget(spec.hosts) {
			m.openHostScope(spec.hosts[0])
		} else if hasNetworkTarget(spec.hosts) {
			m.openHostScope("")
		} else {
			m.screen = "desk"
		}
		m.message = "Запущено: " + spec.label
	}
	return m, nil
}

// --- jobs --------------------------------------------------------------

func (m model) updateJobs(key string) (tea.Model, tea.Cmd) {
	rows := m.jobs
	switch key {
	case "esc", "q":
		m.screen = m.jobsReturn
		if m.screen == "" {
			m.screen = "desk"
		}
	case "up", "k":
		if len(rows) > 0 {
			m.jobIndex = (min(max(0, m.jobIndex), len(rows)-1) + len(rows) - 1) % len(rows)
		}
	case "down", "j":
		if len(rows) > 0 {
			m.jobIndex = (min(max(0, m.jobIndex), len(rows)-1) + 1) % len(rows)
		}
	case "x":
		if m.jobIndex < len(rows) {
			j := rows[m.jobIndex]
			if j.active() && j.cancel != nil {
				j.cancel()
			}
		}
	case "c":
		m.clearFinishedJobs()
		if m.jobIndex >= len(m.jobs) {
			m.jobIndex = max(0, len(m.jobs)-1)
		}
		m.message = "Завершённые задачи очищены"
	case "enter":
		if m.jobIndex < len(rows) {
			m.logOffset = -1
			m.jobDetailRaw = false
			m.jobDetailErrors = false
			m.screen = "job-details"
		}
	case "e":
		if m.jobIndex < len(rows) {
			j := rows[m.jobIndex]
			if j.result == nil || j.runID == 0 {
				m.message = "У этой задачи ещё нет результата"
				return m, nil
			}
			run := domain.Run{ID: j.runID, ProjectID: j.projectID, StartedAt: j.started, FinishedAt: j.ended, Status: j.status, Findings: j.result.Findings, Services: j.result.Services}
			exporter := m
			exporter.current = m.findProject(j.projectID)
			if err := exporter.export(run); err != nil {
				m.message = err.Error()
			} else {
				m.message = "Отчёты сохранены в reports/"
			}
		}
	}
	return m, nil
}

// --- catalog / template picker ------------------------------------------

func (m model) updateCatalogGroups(key string) (tea.Model, tea.Cmd) {
	if m.catalogReadOnly && (key == " " || key == "space" || key == "A" || key == "x") {
		m.message = "Выбор проверок настраивается внутри проекта"
		return m, nil
	}
	groups := m.visibleCatalogGroups()
	switch key {
	case "esc", "left":
		if m.catalogAxis == "impact" && m.catalogDatabase != "" {
			m.catalogAxis = "database"
			m.catalogDatabase, m.catalogImpact, m.search = "", "", ""
			m.catalogGroupIndex = m.databaseGroupIndex
			return m, nil
		}
		if m.catalogAxis == "impact" || m.catalogAxis == "database" {
			m.catalogAxis = "direction"
			m.catalogDirection = ""
			m.catalogImpact = ""
			m.search = ""
			m.catalogGroupIndex = m.serviceGroupIndex
			return m, nil
		}
		m.search = ""
		back := m.catalogBack
		if back == "" {
			back = "desk"
		}
		m.screen = back
	case "home":
		m.catalogGroupIndex = 0
	case "end":
		if m.catalogPending {
			m.catalogGroupIndex = len(groups)
		} else {
			m.catalogGroupIndex = max(0, len(groups)-1)
		}
	case "up", "k":
		if m.catalogGroupIndex > 0 {
			m.catalogGroupIndex--
		}
	case "down", "j":
		if m.catalogGroupIndex+1 < len(groups) || m.catalogPending && m.catalogGroupIndex < len(groups) {
			m.catalogGroupIndex++
		}
	case "1", "t":
		m.catalogDirection, m.catalogImpact, m.catalogDatabase = "", "", ""
		m.catalogAxis = "type"
		m.catalogGroupIndex = 0
	case "2", "p":
		m.catalogDirection, m.catalogImpact, m.catalogDatabase = "", "", ""
		m.catalogAxis = "product"
		m.catalogGroupIndex = 0
	case "3":
		m.catalogDirection, m.catalogImpact, m.catalogDatabase = "", "", ""
		m.catalogAxis = "direction"
		m.catalogGroupIndex = 0
	case "/":
		m.startInput("search")
	case " ", "space":
		if m.catalogGroupIndex < len(groups) {
			ids := m.groupTemplateIDs(groups[m.catalogGroupIndex].Name)
			if len(ids) == 0 {
				m.message = "В этой категории нет доступных проверок. Enter — посмотреть причины."
				return m, nil
			}
			set := m.selectedSet()
			allSelected := true
			for _, id := range ids {
				if !set[id] {
					allSelected = false
					break
				}
			}
			if allSelected {
				ids = m.groupTemplateIDs(groups[m.catalogGroupIndex].Name, true)
			}
			return m, m.bulkIDsCmd(ids, !allSelected)
		}
	case "A":
		// Select every template of every visible group at once.
		var ids []string
		for _, g := range groups {
			ids = append(ids, m.groupTemplateIDs(g.Name)...)
		}
		if len(ids) > 0 {
			return m, m.bulkIDsCmd(uniqueStrings(ids), true)
		}
	case "x":
		var ids []string
		for _, g := range groups {
			ids = append(ids, m.groupTemplateIDs(g.Name, true)...)
		}
		if len(ids) > 0 {
			return m, m.bulkIDsCmd(uniqueStrings(ids), false)
		}
	case "right":
		return m.drillCatalogGroup(groups)
	case "enter":
		// In the one-off scan picker, Enter always jumps straight to launch
		// — no need to navigate down to a trailing "Запустить" row first.
		// Drilling into a group now lives on the right arrow (left/esc backs
		// out), keeping Enter free for "go" and Space for "select" without
		// overloading either key with two different meanings depending on
		// cursor position. In the persistent project-library editor
		// (catalogPending == false) there's no scan to launch, so Enter
		// keeps its old drill-in behavior there.
		if m.catalogPending {
			return m.openScanReview()
		}
		return m.drillCatalogGroup(groups)
	}
	return m, nil
}

// drillCatalogGroup opens the group under the cursor (narrowing the next
// axis, or descending into the flat template list). Bound to both the right
// arrow and Enter (outside the one-off scan picker — see updateCatalogGroups).
func (m model) drillCatalogGroup(groups []libraryGroup) (tea.Model, tea.Cmd) {
	if m.catalogGroupIndex >= len(groups) {
		return m, nil
	}
	group := groups[m.catalogGroupIndex]
	if group.Name == bruteCategoryLabel {
		m.catalogCategory, m.catalogProduct = "", ""
		m.catalogImpact = bruteCategoryLabel
		m.entryIndex = 0
		m.applyFilter()
		m.screen = "catalog"
		return m, nil
	}
	if m.catalogAxis == "database" {
		m.catalogDatabase = group.Name
		m.databaseGroupIndex = m.catalogGroupIndex
		m.catalogGroupIndex = 0
		m.catalogAxis = "impact"
		m.search = ""
		return m, nil
	}
	if m.catalogAxis == "direction" {
		m.catalogCategory, m.catalogProduct, m.catalogImpact = "", "", ""
		m.catalogDirection = group.Name
		m.serviceGroupIndex = m.catalogGroupIndex
		m.catalogGroupIndex = 0
		m.catalogAxis = "impact"
		if group.Name == "Базы данных" {
			m.catalogAxis = "database"
		}
		m.search = ""
		return m, nil
	} else if m.catalogAxis == "impact" {
		m.catalogImpact = group.Name
	} else if m.catalogAxis == "product" {
		m.catalogProduct = group.Name
	} else {
		m.catalogCategory = group.Name
	}
	m.entryIndex = 0
	m.applyFilter()
	m.screen = "catalog"
	return m, nil
}

func (m model) updateCatalog(key string) (tea.Model, tea.Cmd) {
	if m.catalogReadOnly && (key == "enter" || key == " " || key == "space" || key == "A" || key == "x") {
		m.message = "Выбор проверок настраивается внутри проекта"
		return m, nil
	}
	switch key {
	case "esc", "left":
		if m.catalogAxis == "impact" || m.catalogAxis == "database" {
			m.catalogImpact = ""
		} else {
			m.catalogCategory, m.catalogProduct, m.catalogDirection = "", "", ""
			m.catalogImpact = ""
		}
		m.applyFilter()
		m.screen = "catalog-groups"
	case "A":
		return m, m.bulkTemplatesCmd(true)
	case "x":
		return m, m.bulkTemplatesCmd(false)
	case "home":
		m.entryIndex = 0
	case "end":
		if m.catalogPending {
			m.entryIndex = len(m.filtered)
		} else {
			m.entryIndex = max(0, len(m.filtered)-1)
		}
	case "up", "k":
		if m.entryIndex > 0 {
			m.entryIndex--
		}
	case "down", "j":
		if m.entryIndex+1 < len(m.filtered) || m.catalogPending && m.entryIndex < len(m.filtered) {
			m.entryIndex++
		}
	case "enter":
		// Same split as updateCatalogGroups: in the one-off scan picker,
		// Enter always launches immediately regardless of cursor position —
		// Space is the only selection key there. In the persistent
		// project-library editor there's no scan to launch, so Enter keeps
		// toggling the highlighted entry.
		if m.catalogPending {
			return m.openScanReview()
		}
		if m.entryIndex < len(m.filtered) {
			return m, m.toggleCmd(m.filtered[m.entryIndex])
		}
	case " ", "space":
		if m.entryIndex < len(m.filtered) {
			return m, m.toggleCmd(m.filtered[m.entryIndex])
		}
	case "/":
		m.startInput("search")
	case "u":
		return m, m.syncCmd()
	case "d":
		if m.catalogPending {
			return m.openScanReview()
		}
	}
	return m, nil
}

// --- settings ------------------------------------------------------------

// --- history ---------------------------------------------------------

func (m model) updateHistory(key string) (tea.Model, tea.Cmd) {
	m.historyIndex = min(max(0, m.historyIndex), max(0, len(m.history)-1))
	switch key {
	case "esc", "q":
		m.screen = "desk"
	case "up", "k":
		if m.historyIndex > 0 {
			m.historyIndex--
		}
	case "down", "j":
		if m.historyIndex+1 < len(m.history) {
			m.historyIndex++
		}
	case "enter":
		if m.historyIndex >= 0 && m.historyIndex < len(m.history) {
			m.openRunResults(m.history[m.historyIndex].ID)
		}
	case "e":
		if len(m.history) > 0 {
			if err := m.export(m.history[m.historyIndex]); err != nil {
				m.message = err.Error()
			} else {
				m.message = "Отчёты сохранены в reports/"
			}
		}
	}
	return m, nil
}

func serviceBuckets(services []domain.Service) []string {
	out := make([]string, 0, len(services))
	for _, s := range services {
		out = append(out, serviceHostBucket(s, nil))
	}
	return out
}
