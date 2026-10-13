// Package tui implements wscan's interactive terminal interface: a
// separate subnet and host windows, responsive service/result panes, and
// scans running as background jobs instead of blocking the whole screen.
package tui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"wscan/internal/engine/js"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/adscan"
	"wscan/internal/app"
	"wscan/internal/catalog"
	"wscan/internal/dependencies"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/libsync"
	"wscan/internal/report"
	"wscan/internal/storage"
)

type model struct {
	clientSource     string
	shared           *app.Service
	guided           bool
	webURL           string
	wizardStep       int
	wizardIndex      int
	wizardScope      string
	wizardProfile    int
	sidebarEnabled   bool
	reconMenuFocus   bool
	reconMenuIndex   int
	checkMenuIndex   int
	adMenuIndex      int
	reconInfoOffset  int
	reconCardFocus   bool
	reconHostAction  int
	reconFilter      int
	reconIndex       int
	hiddenSharedJobs map[int]bool

	catalogReadOnly      bool
	sshDictionary        sshDictionaryState
	smbBrowser           smbBrowserState
	ftpBrowser           ftpBrowserState
	winrmBrowser         winRMBrowserState
	mssqlConsole         mssqlConsoleState
	pgConsole            pgConsoleState
	mysqlConsole         mysqlConsoleState
	lfiAudit             lfiState
	kyoceraBook          kyoceraState
	interactionIndex     int
	interactionHostIndex int
	interactionReturn    string
	webDiscovery         webDiscoveryState
	sqliForm             sqliFormState
	fileUpload           fileUploadState
	ctx                  context.Context
	store                *storage.Store
	cat                  *catalog.Catalog
	scanner              *engine.Engine
	appDir               string

	screen     string
	helpReturn string
	helpOffset int

	// projects
	projects            []domain.Project
	selected            int
	selectedHosts       map[string]bool
	deleteProjectID     int64
	selectedNetworks    map[string]bool
	hostNames           map[string][]string
	dnsPinned           map[string]bool
	dnsChecked          map[string]time.Time
	dnsBusy             bool
	hostNetwork         string
	networkIndex        int
	current             domain.Project
	settingsIndex       int
	globalSettingsIndex int
	speedReturn         string
	speedIndex          int
	speedPorts          bool
	discProject         domain.Project
	discOnlyKnown       bool
	deleteHost          string
	deleteNetwork       string
	deleteService       *domain.Service
	exclusions          []inventoryExclusion
	inventoryResets     []storage.InventoryReset

	// desk: aggregated view across every run of the current project
	hostOrder                []string
	inventory                map[string]*hostInfo
	hostIndex                int // -1 means "All hosts"
	serviceIndex             int
	preferredPort            int
	preferredProtocol        string
	serviceInventoryIndex    int
	serviceInventoryFilter   string
	serviceInventoryProject  bool
	serviceInventoryEditing  bool
	serviceInventorySelected map[string]bool
	projectResultsReturn     string
	findingDetailFocus       bool // right pane scrolls; otherwise arrows select a finding
	findingDirectReturn      bool // opened from a host result rather than the result list
	resultsScope             resultScope
	projectResultsSearch     string
	projectResultsFilter     string
	projectResultsSelected   map[string]bool
	resultDeleteConfirm      bool
	resultDeleting           bool
	resultDeleteGeneration   int
	resultDeleteCount        int
	resultDeleteFindings     []domain.Finding
	findingIndex             int
	focusCol                 int // 0 hosts, 1 services, 2 details/findings
	findingDetail            *domain.Finding
	findingOffset            int
	findingMetadata          bool
	findingTemplatePath      string
	findingImpact            string
	findingRemediation       string
	findingClassified        string
	findingSection           int // 0 overview, 1 evidence, 2 recommendations
	findingRaw               bool
	findingPane              int // 0 result list, 1 detail scrolling

	// background jobs
	jobs            []*job
	jobSeq          int
	jobEvents       chan jobEvent
	jobIndex        int
	jobsReturn      string
	logOffset       int
	jobDetailRaw    bool
	jobDetailErrors bool

	// Local Active Directory discovery window. The scan is unauthenticated,
	// read-only, and restricted to a selected private IPv4 interface subnet.
	adNetworks                                       []adscan.Network
	adNetworkIndex                                   int
	adScanDNS                                        adscan.DNSOptions
	adScanAdvanced                                   bool
	adScanNewProject                                 bool
	adScanRunning                                    bool
	adScanDone                                       int
	adScanTotal                                      int
	adScanResult                                     *adscan.Result
	adScanError                                      string
	adScanReturn                                     string
	adScanJobID                                      int
	adAccessReturn                                   string
	adBloodHoundPort, adBloodHoundLimit              int
	adAccessHost                                     string
	adAccessDomain                                   string
	adAccessLDAPPort                                 int
	adAccessGeneration                               int
	adAccessAutoBusy                                 bool
	adAccessHint                                     string
	adAccessAutoHost                                 string
	adAccessManualHost                               string
	adControllerReturn                               string
	adControllerIndex                                int
	adAccessNodes                                    []adscan.Host
	adAccessNodesProject                             int64
	adCoerceCallback                                 string
	adAccessIndex                                    int
	adAccessCreds                                    []domain.Credential
	adAccessCred                                     int
	adAccessJobID                                    int
	adASREPIndex                                     int
	adASREPUsers                                     string
	adResponderJobID                                 int
	responderDebug                                   bool
	coerceActionIndex                                int
	coerceCallbackAuto                               bool
	coercePortGeneration                             int
	coercePortAction, coercePortIP, coercePortReturn string
	coercePortApproved                               bool
	coercePortOwners                                 []adscan.PortOwner
	coercePortLease                                  *adscan.PortLease
	coercePortCancel                                 context.CancelFunc

	// action menu (opened with Enter)
	bulkPort      int
	bulkProtocol  string
	actionIndex   int
	actionReturn  string
	actionHosts   []string
	actionService *domain.Service

	// discovery options (opened before launching a Discover action)
	discReturn   string
	discOptIndex int
	discSetIndex int // 0 common, 1 top100, 2 top1000, 3 all, 4 custom
	discCustom   string
	discTCP      bool
	discUDP      bool
	discVersion  bool
	discNoPing   bool
	discHosts    []string

	// template catalog / picker, shared between project-default management
	// ('t' from the desk) and one-off per-action selection (from the action
	// menu). catalogPending selects which of those two the picker feeds.
	entries              []catalog.Entry
	filtered             []catalog.Entry
	entryIndex           int
	search               string
	catalogFamily        string
	catalogCategory      string
	catalogProduct       string
	catalogDatabase      string
	databaseGroupIndex   int
	catalogDirection     string
	catalogImpact        string
	serviceGroupIndex    int
	catalogLoadError     string
	librarySyncing       bool
	libraryStatus        libsync.Status
	libraryStatusLoading bool
	libraryError         string
	interpreters         []dependencies.Interpreter
	dependenciesLoading  bool
	dependencyIndex      int
	dependencyError      string
	dependencyPlan       dependencies.Plan
	scanReviewReturn     string
	scanReviewProject    domain.Project
	scanReviewReady      bool
	scanReviewIndex      int
	catalogAxis          string
	catalogGroupIndex    int
	catalogBack          string
	catalogPending       bool

	pendingTemplateIDs []string

	// text input
	input       string
	inputAction string
	inputReturn string

	// host repair (fixes a target string with invalid UTF-8 saved earlier)
	repairOld string
	repairNew string

	history      []domain.Run
	historyIndex int

	// credentials (post-auth spray/modules — internal/engine.SprayCredentials/
	// RunModule)
	credentials     []domain.Credential
	credIndex       int
	credEditID      int64
	credNewNotes    string
	credDeleteID    int64
	credNewType     string
	credNewUsername string
	credNewDomain   string
	credNewSecret   string

	// credential-attack (spray + post-auth modules) against one target
	sprayTarget        *domain.Service
	sprayCredentials   []domain.Credential
	sprayChecked       map[int64]bool
	sprayCredIndex     int
	spraySelectedCreds []domain.Credential
	sprayResults       []domain.AuthAttempt
	sprayResultIndex   int
	sprayModules       []engine.ModuleInfo
	sprayModuleIndex   int
	sprayModuleAttempt *domain.AuthAttempt
	sprayModuleArgs    map[string]string
	sprayModuleResult  *domain.ModuleResult

	message           string
	width             int
	height            int
	credentialsReturn string
}

func Run(ctx context.Context, s *storage.Store, c *catalog.Catalog, scan *engine.Engine, dir string) (runErr error) {
	service, err := app.NewService(ctx, s, c, scan, filepath.Join(dir, "exports", "ad"))
	if err != nil {
		return err
	}
	defer service.Close()
	return RunWithService(ctx, s, c, scan, dir, service, "")
}
func RunWithService(ctx context.Context, s *storage.Store, c *catalog.Catalog, scan *engine.Engine, dir string, service *app.Service, webURL string) (runErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer func() { cancel(); runErr = errors.Join(runErr, adscan.RestoreCoercionPorts()) }()
	m := model{
		ctx:    ctx,
		shared: service, guided: true, webURL: webURL,
		store:     s,
		cat:       c,
		scanner:   scan,
		appDir:    dir,
		screen:    "projects",
		height:    24,
		jobEvents: make(chan jobEvent, 16),
		message:   "Нажми n, чтобы создать проект, затем добавь хосты.",
	}
	if err := m.reload(); err != nil {
		return err
	}
	if webURL != "" {
		m.screen = "web-connect"
		m.message = "Открываю браузер…"
	}
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx))
	_, err := p.Run()
	return err
}

func (m *model) reload() error {
	ps, err := m.store.ListProjects(m.ctx)
	if err == nil {
		m.projects = ps
	}
	return err
}

func (m model) Init() tea.Cmd {
	commands := []tea.Cmd{waitForJob(m.jobEvents), tickJobs(), m.loadCatalogCmd()}
	if m.screen == "web-connect" && m.webURL != "" {
		commands = append(commands, openWebBrowser(m.webURL))
	}
	return tea.Batch(commands...)
}

func (m model) findProject(id int64) domain.Project {
	for _, p := range m.projects {
		if p.ID == id {
			return p
		}
	}
	return domain.Project{ID: id}
}

// openProject loads a project onto the desk: history, inventory, jobs view.
func (m *model) openProject(p domain.Project) {
	m.current = p
	m.adAccessGeneration++
	m.adAccessAutoBusy = false
	m.adAccessNodes, m.adAccessNodesProject = nil, 0
	m.adAccessHost, m.adAccessDomain, m.adAccessAutoHost, m.adAccessHint = "", "", "", ""
	m.loadADControllerSelection()
	m.selectedHosts = nil
	m.selectedNetworks = nil
	m.hostNetwork = ""
	m.networkIndex = 0
	m.history, _ = m.store.Runs(m.ctx, p.ID)
	m.historyIndex = 0
	m.loadInventory()
	m.hostIndex = 0
	if len(m.hostOrder) == 0 {
		m.hostIndex = -1
	}
	m.serviceIndex = 0
	m.preferredPort, m.preferredProtocol = 0, ""
	m.findingIndex = 0
	m.projectResultsSearch = ""
	m.resultsScope = resultScope{}
	m.projectResultsSelected = nil
	m.resultDeleteConfirm = false
	m.resultDeleting = false
	m.resultDeleteGeneration++
	m.projectResultsFilter = "important"
	m.focusCol = 0
	m.screen = "desk"
	m.sidebarEnabled = true
	m.reconIndex, m.reconFilter = 0, 0
	m.reconCardFocus = false
	m.reconMenuFocus = len(m.hostOrder) == 0
	m.reconMenuIndex = 0
	m.message = ""
}

// --- text input -------------------------------------------------------

func (m *model) startInput(action string) {
	m.inputReturn = m.screen
	m.inputAction = action
	m.input = ""
	if m.credEditID != 0 {
		switch action {
		case "cred-username":
			m.input = m.credNewUsername
		case "cred-domain":
			m.input = m.credNewDomain
		case "cred-secret":
			m.input = m.credNewSecret
		case "cred-notes":
			m.input = m.credNewNotes
		}
	}
	m.screen = "input"
}

func (m model) inputBack() string {
	if m.inputReturn != "" {
		return m.inputReturn
	}
	return "desk"
}

func (m model) updateInput(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.Type {
	case tea.KeyEsc:
		m.screen = m.inputBack()
		m.input = ""
		return m, nil
	case tea.KeyEnter:
		value := strings.TrimSpace(m.input)
		if m.inputAction == "cred-secret" {
			value = m.input
		}
		action := m.inputAction
		m.input = ""
		m.screen = m.inputBack()
		// cred-domain and cred-notes are optional (a local account has no AD
		// domain; notes are just a free-text label). cred-username and
		// cred-secret must also accept empty: SMB/LDAP/VNC anonymous or null-
		// session login (nxc's `-u '' -p ''`) IS blank username/password, not
		// a special credential type — rejecting empty here would make that
		// case impossible to save. Every other action still treats empty
		// input as "cancel this step".
		isCred := strings.HasPrefix(action, "cred-")
		if value == "" && !strings.HasPrefix(action, "ad-recon-") && !isCred && action != "ad-access-host" && action != "asrep-users" && action != "project-results-search" && action != "lfi-vhost" && action != "mysql-user" && action != "mysql-database" && !strings.HasPrefix(action, "web-discovery-") && action != "web-wordlist-filter" && !strings.HasPrefix(action, "ssh-dict-") {
			return m, nil
		}
		switch action {
		case "select-host-port":
			port, protocol, err := parseSinglePort(value)
			if err != nil {
				m.screen = "input"
				m.input = value
				m.message = err.Error()
				return m, nil
			}
			m.screen = "desk"
			m.selectMatchingHosts("port", port, protocol)
			return m, nil
		case "ptr-server":
			server, err := discovery.DNSServerAddress(value)
			if err != nil {
				m.message = err.Error()
				return m, nil
			}
			spec := launchSpec{kind: jobPTR, label: "PTR: " + strings.Join(m.actionHosts, ", "), hosts: append([]string(nil), m.actionHosts...), dnsServer: server}
			m.startLaunch(spec)
			m.screen = "networks"
			m.message = "Запущено: " + spec.label
			return m, nil
		case "ssh-dict-user":
			m.sshDictionary.options.Username = value
			return m, nil
		case "ssh-dict-users":
			m.sshDictionary.options.Userlist = value
			return m, nil
		case "ssh-dict-passwords":
			m.sshDictionary.options.Passwordlist = value
			m.screen = "ssh-dictionary"
			return m, nil
		case "ssh-dict-port":
			port, protocol, err := parseSinglePort(value)
			if err != nil || protocol != "tcp" {
				m.message = "Укажи TCP-порт от 1 до 65535"
				return m, nil
			}
			m.sshDictionary.target.Port = port
			return m, nil
		case "ssh-dict-rps", "ssh-dict-workers":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 10000 || (action == "ssh-dict-workers" && (n < 1 || n > 64)) {
				m.message = "RPS: 0–10000; потоки: 1–64"
				return m, nil
			}
			if action == "ssh-dict-rps" {
				m.sshDictionary.options.RPS = n
			} else {
				m.sshDictionary.options.Concurrency = n
			}
			return m, nil
		case "ssh-dict-delay":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 60000 {
				m.message = "Пауза: 0–60000 мс"
				return m, nil
			}
			m.sshDictionary.options.Delay = time.Duration(n) * time.Millisecond
			return m, nil
		case "web-discovery-url":
			m.webDiscovery.options.URL = value
			return m, nil
		case "web-wordlist-filter":
			m.webDiscovery.wordlistFilter = value
			m.webDiscovery.wordlistIndex = 0
			return m, nil
		case "web-discovery-wordlist":
			m.webDiscovery.options.Wordlist = value
			m.screen = "web-discovery"
			return m, nil
		case "web-discovery-extensions":
			m.webDiscovery.options.Extensions = value
			return m, nil
		case "web-discovery-vhost":
			m.webDiscovery.options.VirtualHost = value
			return m, nil
		case "web-discovery-statuses":
			m.webDiscovery.options.Statuses = value
			return m, nil
		case "web-discovery-sizes":
			m.webDiscovery.options.ExcludeSizes = value
			return m, nil
		case "web-discovery-rps", "web-discovery-workers":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || (action == "web-discovery-workers" && (n < 1 || n > 64)) || n > 10000 {
				m.message = "RPS: 0–10000; потоки: 1–64"
				return m, nil
			}
			if action == "web-discovery-rps" {
				m.webDiscovery.options.RPS = n
			} else {
				m.webDiscovery.options.Concurrency = n
			}
			return m, nil
		case "sqli-form-url":
			m.sqliForm.options.URL = value
			return m, nil
		case "sqli-form-vhost":
			m.sqliForm.options.VirtualHost = value
			return m, nil
		case "sqli-form-cookie":
			m.sqliForm.options.Cookie = value
			return m, nil
		case "sqli-form-workers":
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 8 {
				m.message = "Потоки: 1–8"
				return m, nil
			}
			m.sqliForm.options.Concurrency = n
			return m, nil
		case "file-upload-url":
			m.fileUpload.options.URL = value
			return m, nil
		case "file-upload-vhost":
			m.fileUpload.options.VirtualHost = value
			return m, nil
		case "file-upload-cookie":
			m.fileUpload.options.Cookie = value
			return m, nil
		case "file-upload-workers":
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 8 {
				m.message = "Потоки: 1–8"
				return m, nil
			}
			m.fileUpload.options.Concurrency = n
			return m, nil
		case "lfi-url":
			m.lfiAudit.options.URL = value
			return m, nil
		case "lfi-parameter":
			m.lfiAudit.options.Parameter = value
			return m, nil
		case "lfi-vhost":
			m.lfiAudit.options.VirtualHost = value
			return m, nil
		case "kyocera-port":
			port, protocol, err := parseSinglePort(value)
			if err != nil || protocol != "tcp" {
				m.message = "Нужен один TCP-порт"
				return m, nil
			}
			m.kyoceraBook.target.Port = port
			return m, nil
		case "kyocera-wait":
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || n < 0 || n > 60 {
				m.message = "Пауза: число секунд 0–60"
				return m, nil
			}
			m.kyoceraBook.options.WaitSecs = n
			return m, nil
		case "mysql-port":
			port, protocol, err := parseSinglePort(value)
			if err != nil || protocol != "tcp" {
				m.message = "Укажи TCP-порт от 1 до 65535"
				return m, nil
			}
			m.mysqlConsole.options.Port = port
			return m, nil
		case "mysql-user":
			m.mysqlConsole.options.Username = value
			return m, nil
		case "mysql-query":
			return m.startMySQL("query", value)
		case "mysql-database":
			if m.screen == "mysql-setup" {
				m.mysqlConsole.options.Database = value
				return m, nil
			}
			return m.startMySQL("database", value)
		case "pg-port":
			port, protocol, err := parseSinglePort(value)
			if err != nil || protocol != "tcp" {
				m.message = "Укажи TCP-порт от 1 до 65535"
				return m, nil
			}
			m.pgConsole.options.Port = port
			return m, nil
		case "pg-user":
			m.pgConsole.options.Username = value
			return m, nil
		case "pg-query":
			return m.startPG("query", value)
		case "pg-database":
			if m.screen == "pg-setup" {
				m.pgConsole.options.Database = value
				return m, nil
			}
			return m.startPG("database", value)
		case "mssql-port":
			port, protocol, err := parseSinglePort(value)
			if err != nil || protocol != "tcp" {
				m.message = "Укажи TCP-порт от 1 до 65535"
				return m, nil
			}
			m.mssqlConsole.options.Port = port
			return m, nil
		case "ftp-port":
			port, protocol, err := parseSinglePort(value)
			if err != nil || protocol != "tcp" {
				m.message = "Укажи TCP-порт от 1 до 65535"
				return m, nil
			}
			m.ftpBrowser.options.Port = port
			m.ftpBrowser.connected = false
			return m, nil
		case "ftp-path":
			return m.startFTPOperation("list", value, "")
		case "smb-port":
			port, protocol, err := parseSinglePort(value)
			if err != nil || protocol != "tcp" {
				m.message = "Укажи TCP-порт от 1 до 65535"
				return m, nil
			}
			m.smbBrowser.port = port
			return m.loadSMBDirectory("", "")
		case "module-share":
			return m.runSelectedModule(map[string]string{"share": value})
		case "mssql-nse":
			return m.startMSSQL("nse", value)
		case "mssql-columns":
			return m.startMSSQL("query", ":columns "+value)
		case "mssql-rows":
			return m.startMSSQL("query", ":rows "+value)
		case "mssql-count":
			return m.startMSSQL("query", ":count "+value)
		case "mssql-transfer-local":
			m.mssqlConsole.transferLocal = value
			m.startInput("mssql-transfer-address")
			m.input = m.mssqlConsole.transferAddress
			if m.input == "" {
				m.input = js.HTTPAddressForTarget(m.mssqlConsole.options.Host)
			}
		case "mssql-transfer-address":
			if net.ParseIP(value) == nil {
				m.message = "Укажи IP, доступный Windows-хосту"
				return m, nil
			}
			m.mssqlConsole.transferAddress = value
			m.startInput("mssql-transfer-port")
			m.input = "8000"
		case "mssql-transfer-port":
			port, protocol, err := parseSinglePort(value)
			if err != nil || protocol != "tcp" {
				m.message = "Укажи TCP-порт 1–65535"
				return m, nil
			}
			m.mssqlConsole.transferPort = port
			m.startInput("mssql-transfer-remote")
			m.input = `%TEMP%\` + filepath.Base(m.mssqlConsole.transferLocal)
		case "mssql-transfer-remote":
			m.mssqlConsole.transferRemote = value
			return m.startMSSQL("transfer", value)
		case "mssql-winpeas":
			m.mssqlConsole.winpeasPath = value
			m.mssqlConsole.reportPath = value + ".txt"
			m.mssqlConsole.reportOffset = 0
			return m.startMSSQL("winpeas", mssqlPowerShellQuery(mssqlWinPEASScript(value)))
		case "mssql-report":
			m.mssqlConsole.reportPath = value
			m.mssqlConsole.reportOffset = 0
			return m.startMSSQL("report", mssqlPowerShellQuery(mssqlReportScript(value, 0)))
		case "mssql-command":
			return m.startMSSQL("query", mssqlCommandQuery(value))
		case "mssql-query":
			return m.startMSSQL("query", value)
		case "mssql-database":
			return m.startMSSQL("database", value)
		case "winrm-port":
			port, protocol, err := parseSinglePort(value)
			if err != nil || protocol != "tcp" {
				m.message = "Укажи TCP-порт от 1 до 65535"
				return m, nil
			}
			m.winrmBrowser.options.Port = port
			return m, nil
		case "winrm-path":
			return m.startWinRMOperation("list", value, "")
		case "winrm-shell-command":
			return m.startWinRMOperation("shell-command", value, "")
		case "winrm-command":
			return m.startWinRMOperation("command", value, "Вывод PowerShell")
		case "bulk-port":
			return m.saveBulkPort(value)
		case "setting-value":
			return m.saveSettingValue(value)
		case "disc-setting-value":
			return m.saveDiscSettingValue(value)
		case "scan-setting-value":
			return m.saveScanSettingValue(value)
		case "new-project":
			id, err := m.store.CreateProject(m.ctx, value)
			if err != nil {
				m.message = err.Error()
			} else {
				_ = m.reload()
				m.openProject(m.findProject(id))
				m.message = "Проект создан."
			}
		case "guided-scope":
			m.wizardScope = value
			m.screen = "guided-scan"
			if m.wizardStep == 0 {
				m.wizardIndex = 1
			} else {
				m.wizardIndex = 0
			}
			return m, nil
		case "ad-recon-dns", "ad-recon-domains", "ad-recon-budget":
			options := m.adScanDNS
			values := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' })
			if action == "ad-recon-dns" {
				options.Servers = values
			}
			if action == "ad-recon-domains" {
				options.Domains = values
			}
			if action == "ad-recon-budget" {
				budget, err := strconv.Atoi(value)
				if err != nil {
					m.message = "Лимит DNS-запросов: целое число 1–100000"
					return m, nil
				}
				options.MaxQueries = budget
				if budget < 1 {
					m.message = "Лимит DNS-запросов: 1–100000"
					return m, nil
				}
			}
			normalized, err := adscan.ValidateDNSOptions(options)
			if err != nil {
				m.message = err.Error()
				return m, nil
			}
			m.adScanDNS = normalized
			m.message = "Параметры AD-разведки обновлены"
			return m, nil
		case "ad-cidr":
			network, err := adscan.ValidatePrivateSubnet(value)
			if err != nil {
				m.message = err.Error()
				return m, nil
			}
			for i, existing := range m.adNetworks {
				if existing.CIDR == network.CIDR {
					m.adNetworkIndex = i
					m.message = "Выбрана подсеть " + network.CIDR
					return m, nil
				}
			}
			m.adNetworks = append(m.adNetworks, network)
			m.adNetworkIndex = len(m.adNetworks) - 1
			m.message = "Выбрана подсеть " + network.CIDR + ". Нажми Enter для сканирования."
		case "ad-bloodhound-limit":
			limit, err := strconv.Atoi(value)
			if err != nil || limit < 1 || limit > 50000 {
				m.message = "Лимит BloodHound: 1–50000"
				return m, nil
			}
			m.adBloodHoundLimit = limit
			m.screen = "ad-access"
		case "ad-access-host":
			if m.inputReturn != "coerce-setup" {
				if err := m.setADController(value); err != nil {
					m.message = err.Error()
					return m, nil
				}
				return m, m.detectADAccessIdentityCmd()
			}
			m.adAccessGeneration++
			m.adAccessAutoBusy, m.adAccessHint = false, ""
			m.adAccessAutoHost = ""
			m.adAccessHost = value
			m.screen = "coerce-setup"
		case "asrep-users":
			m.adASREPUsers = value
			m.screen = "asrep-setup"
		case "ad-coerce-callback":
			m.adCoerceCallback = value
			m.coerceCallbackAuto = false
			m.screen = "ad-access"
			if m.inputReturn == "coerce-setup" {
				m.screen = "coerce-setup"
			}
		case "ad-access-domain":
			m.adAccessGeneration++
			m.adAccessAutoBusy, m.adAccessHint = false, ""
			m.adAccessAutoHost = ""
			m.adAccessDomain = value
			if m.inputReturn != "coerce-setup" && m.adAccessManualHost != "" {
				m.adAccessHost = m.adAccessManualHost
				if err := m.store.SetADController(m.ctx, m.current.ID, m.adAccessManualHost, value); err != nil {
					m.message = err.Error()
				}
			} else if m.inputReturn != "coerce-setup" && m.adAccessNodesProject == m.current.ID {
				m.adAccessHost = ""
				m.chooseADAccessIdentity(m.adAccessNodes)
			}
			m.screen = "ad-access"
			if m.inputReturn == "coerce-setup" {
				m.screen = "coerce-setup"
			}
			if m.inputReturn == "asrep-setup" {
				m.screen = "asrep-setup"
			}
		case "add-target", "add-network":
			if !utf8.ValidString(value) {
				m.message = "Недопустимый символ в адресе. Введи хост заново."
			} else if action == "add-network" && !discovery.IsNetworkTarget(value) {
				m.message = "Укажи подсеть в формате CIDR, например 10.0.0.0/24."
			} else if err := discovery.ValidateTarget(value); err != nil {
				m.message = "Некорректная цель: " + err.Error()
			} else if err := m.store.AddTarget(m.ctx, m.current.ID, value); err != nil {
				m.message = err.Error()
			} else {
				_ = m.reload()
				m.current = m.findProject(m.current.ID)
				if !discovery.IsNetworkTarget(value) {
					host, _ := discovery.TargetHost(value)
					if err := m.store.RestoreInventoryHost(m.ctx, m.current.ID, host); err != nil {
						m.message = "Хост добавлен, но список не восстановлен: " + err.Error()
						return m, nil
					}
				}
				m.loadInventory()
				if discovery.IsNetworkTarget(value) {
					for i, network := range m.networkTargets() {
						if network == value {
							m.networkIndex = i
							break
						}
					}
					m.screen = "networks"
					m.message = "Подсеть добавлена. Enter → найти живые хосты."
				} else {
					m.openHostScope("")
					host, _ := discovery.TargetHost(value)
					m.selectHost(host)
					m.message = "Хост добавлен."
				}
			}
		case "project-results-search":
			m.projectResultsSelected = nil
			m.findingPane = 0
			m.projectResultsSearch = value
			m.screen = "project-results"
			m.findingIndex = 0
			m.refreshProjectResultSelection()
		case "search":
			m.search = value
			m.catalogGroupIndex, m.entryIndex = 0, 0
			m.applyFilter()
			m.screen = m.inputBack()
		case "disc-ports":
			m.discCustom = value
			m.discSetIndex = 4
		case "cred-username":
			m.credNewUsername = value
			m.startInput("cred-domain")
		case "cred-domain":
			m.credNewDomain = value
			m.startInput("cred-secret")
		case "cred-secret":
			m.credNewSecret = value
			m.startInput("cred-notes")
		case "cred-notes":
			return m.saveCredential(value)
		case "module-command":
			return m.runSelectedModule(map[string]string{"command": value})
		}
		return m, nil
	case tea.KeyBackspace:
		if len(m.input) > 0 {
			runes := []rune(m.input)
			m.input = string(runes[:len(runes)-1])
		}
		return m, nil
	case tea.KeyCtrlU:
		m.input = ""
		return m, nil
	case tea.KeySpace:
		m.input += " "
		return m, nil
	case tea.KeyRunes:
		m.input += string(k.Runes)
		return m, nil
	}
	return m, nil
}

func (m *model) selectHost(host string) {
	for i, h := range m.hostOrder {
		if h == host {
			m.hostIndex = i
			return
		}
	}
}

// --- catalog / template picker -----------------------------------------

type syncDone struct {
	entries []catalog.Entry
	err     error
}
type libraryUpdateDone struct {
	cfg libsync.Config
	err error
}
type templateDone struct {
	entry catalog.Entry
	err   error
}
type bulkTemplatesDone struct {
	selected bool
	count    int
	ids      []string
	err      error
}
type libraryGroup struct {
	Name      string
	Count     int
	Available int
}

func (m model) loadCatalogCmd() tea.Cmd {
	return func() tea.Msg { entries, err := m.cat.List(); return syncDone{entries, err} }
}

func (m model) syncCmd() tea.Cmd {
	return func() tea.Msg { entries, err := m.cat.Sync(m.ctx); return syncDone{entries, err} }
}

func (m model) downloadLibraryCmd() tea.Cmd {
	appDir := m.appDir
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, 15*time.Minute)
		defer cancel()
		cfg, err := libsync.UpdateContext(ctx, appDir, "", "")
		return libraryUpdateDone{cfg: cfg, err: err}
	}
}

func (m model) toggleCmd(e catalog.Entry) tea.Cmd {
	return func() tea.Msg {
		if e.Checked && !e.Available && !m.selectedSet()[e.Path] {
			return templateDone{e, fmt.Errorf("Недоступно: %s", e.Reason)}
		}
		b, err := m.cat.Load(m.ctx, e.Path)
		if err != nil {
			return templateDone{e, err}
		}
		if !e.Checked && !m.selectedSet()[e.Path] {
			if available, reason := catalog.CheckWithLibrary(b, e.Path, m.cat.LibraryDir()); !available {
				return templateDone{e, fmt.Errorf("Недоступно: %s", reason)}
			}
		}
		// Selection follows the compatibility information from the local library.
		return templateDone{entry: e}
	}
}

func (m model) bulkTemplatesCmd(selected bool) tea.Cmd {
	ids := make([]string, 0, len(m.filtered))
	for _, entry := range m.filtered {
		if !selected || !entry.Checked || entry.Available {
			ids = append(ids, entry.Path)
		}
	}
	return m.bulkIDsCmd(ids, selected)
}

// bulkIDsCmd selects or clears an explicit set of template IDs, routing to the
// project store or the one-off pending selection depending on catalog mode.
func (m model) bulkIDsCmd(ids []string, selected bool) tea.Cmd {
	return func() tea.Msg {
		if m.catalogPending {
			return bulkTemplatesDone{selected: selected, count: len(ids), ids: ids}
		}
		err := m.store.SetTemplates(m.ctx, m.current.ID, ids, selected)
		return bulkTemplatesDone{selected: selected, count: len(ids), ids: ids, err: err}
	}
}

// selectedSet is the currently-selected template set for the active catalog
// mode (one-off pending action, or the project's default library).
func (m model) selectedSet() map[string]bool {
	if m.catalogReadOnly {
		return map[string]bool{}
	}
	sel := m.current.TemplateIDs
	if m.catalogPending {
		sel = m.pendingTemplateIDs
	}
	out := make(map[string]bool, len(sel))
	for _, id := range sel {
		out[id] = true
	}
	return out
}

// groupValues returns the group name(s) an entry belongs to on the current axis,
// matching how visibleCatalogGroups buckets entries.
func (m model) groupValues(e catalog.Entry) []string {
	// Keep unsupported templates out of normal Web/product/type buckets unless
	// the user opened the dedicated "Неподдерживаемые" service group.
	if catalog.IsUnsupported(e) && m.catalogDirection != catalog.UnsupportedGroup {
		if m.catalogAxis == "direction" {
			return []string{catalog.UnsupportedGroup}
		}
		if m.catalogAxis == "type" || m.catalogAxis == "product" {
			return []string{catalog.UnsupportedGroup}
		}
		if (m.catalogAxis == "impact" || m.catalogAxis == "database") && m.catalogDirection == "" {
			return []string{catalog.UnsupportedGroup}
		}
	}
	// Credential guessing is a standalone choice on every catalog axis.
	// This prevents selecting a whole service/product/type group from
	// silently including brute-force checks.
	if isBruteEntry(e) {
		return []string{bruteCategoryLabel}
	}
	if m.catalogAxis == "database" {
		return []string{catalog.DatabaseType(e)}
	}
	if m.catalogAxis == "impact" {
		// Carve credential-guessing checks (smb-default-login.yaml and the
		// other "Подбор учётных данных" entries — see isBruteEntry) out of
		// their usual Обнаружение/Активные проверки/Сильное воздействие
		// bucket into their own, the same way IsUnsupported is carved out
		// above: a bruteforce check buried under "Сильное воздействие"
		// alongside real RCEs is easy to miss when deciding whether to
		// include it in a scan, so it gets its own visible bucket right
		// here on the impact screen instead of only being distinguishable
		// on the separate "by type" axis.
		return []string{catalog.Impact(e)}
	}
	if m.catalogAxis == "direction" {
		return []string{catalog.Direction(e)}
	}
	if m.catalogAxis == "product" {
		var vals []string
		seen := map[string]bool{}
		for _, v := range strings.Split(e.Product, ",") {
			v = strings.TrimSpace(v)
			if v != "" && !seen[v] {
				seen[v] = true
				vals = append(vals, v)
			}
		}
		return vals
	}
	// Reviewed Web groups are additional choices beside the original type.
	// Preserve the existing combined category labels for other entries.
	if e.Service == "Web" && strings.Contains(e.Type, "Web: ") {
		var values []string
		for _, value := range strings.Split(e.Type, ",") {
			if value = strings.TrimSpace(value); value != "" {
				values = append(values, value)
			}
		}
		return uniqueStrings(values)
	}
	return []string{strings.TrimSpace(e.Type)}
}

func (m model) inCurrentFamily(e catalog.Entry) bool {
	if m.catalogAxis == "impact" && m.catalogDirection != "" && catalog.Direction(e) != m.catalogDirection {
		return false
	}
	if m.catalogDatabase != "" && catalog.DatabaseType(e) != m.catalogDatabase {
		return false
	}
	isNSE := strings.HasPrefix(e.Path, "nmap/scripts/")
	if m.catalogFamily == "nmap" && !isNSE {
		return false
	}
	if m.catalogFamily == "nuclei" && isNSE {
		return false
	}
	return true
}

// groupCounts returns, per group name on the current axis, how many templates it
// has and how many are currently selected (for checkbox rendering).
func (m model) groupCounts() (total, selected map[string]int) {
	total = map[string]int{}
	selected = map[string]int{}
	set := m.selectedSet()
	seenPaths := map[string]bool{}
	for _, e := range m.entries {
		if e.Path != "" {
			if seenPaths[e.Path] {
				continue
			}
			seenPaths[e.Path] = true
		}
		if !m.inCurrentFamily(e) || e.Checked && !e.Available {
			continue
		}
		for _, g := range m.groupValues(e) {
			if g == "" {
				continue
			}
			total[g]++
			if set[e.Path] {
				selected[g]++
			}
		}
	}
	return
}

// groupTemplateIDs returns every template path belonging to a group on the
// current axis.
func (m model) groupTemplateIDs(name string, includeUnavailable ...bool) []string {
	var ids []string
	all := len(includeUnavailable) > 0 && includeUnavailable[0]
	seenPaths := map[string]bool{}
	for _, e := range m.entries {
		if e.Path != "" {
			if seenPaths[e.Path] {
				continue
			}
			seenPaths[e.Path] = true
		}
		if !m.inCurrentFamily(e) || !all && e.Checked && !e.Available {
			continue
		}
		for _, g := range m.groupValues(e) {
			if g == name {
				ids = append(ids, e.Path)
				break
			}
		}
	}
	return ids
}

func entryHasType(entry catalog.Entry, category string) bool {
	if strings.HasPrefix(category, "Web: ") && isBruteEntry(entry) {
		return false
	}
	// The "type" axis in visibleCatalogGroups groups NSE scripts by their
	// whole comma-joined category set as one label (e.g. "Fuzzing,
	// Интенсивные проверки" for a script tagged both fuzzer and intrusive),
	// so a group selection must match that whole string, not one token of it.
	if strings.TrimSpace(entry.Type) == category {
		return true
	}
	for _, value := range strings.Split(entry.Type, ",") {
		if strings.TrimSpace(value) == category {
			return true
		}
	}
	return false
}

func entryHasProduct(entry catalog.Entry, product string) bool {
	for _, value := range strings.Split(entry.Product, ",") {
		if strings.TrimSpace(value) == product {
			return true
		}
	}
	return false
}

func (m *model) applyFilter() {
	m.filtered = m.filtered[:0]
	q := strings.ToLower(m.search)
	seenPaths := map[string]bool{}
	for _, e := range m.entries {
		if e.Path != "" {
			if seenPaths[e.Path] {
				continue
			}
			seenPaths[e.Path] = true
		}
		isNSE := strings.HasPrefix(e.Path, "nmap/scripts/")
		familyOK := m.catalogFamily == "" || (m.catalogFamily == "nmap" && isNSE) || (m.catalogFamily == "nuclei" && !isNSE)
		categoryOK := m.catalogCategory == "" ||
			(m.catalogCategory == catalog.UnsupportedGroup && catalog.IsUnsupported(e)) ||
			entryHasType(e, m.catalogCategory)
		productOK := m.catalogProduct == "" ||
			(m.catalogProduct == catalog.UnsupportedGroup && catalog.IsUnsupported(e)) ||
			entryHasProduct(e, m.catalogProduct)
		searchable := strings.ToLower(e.Path + " " + e.Category + " " + e.Type + " " + e.Product + " " + e.SearchText + " " + catalog.Direction(e) + " " + e.Reason)
		directionOK := m.catalogDirection == "" || catalog.Direction(e) == m.catalogDirection
		impactOK := m.catalogImpact == "" ||
			m.catalogImpact == bruteCategoryLabel && isBruteEntry(e) ||
			catalog.Impact(e) == m.catalogImpact
		databaseOK := m.catalogDatabase == "" || catalog.DatabaseType(e) == m.catalogDatabase
		if familyOK && categoryOK && productOK && directionOK && impactOK && databaseOK && (q == "" || strings.Contains(searchable, q)) {
			m.filtered = append(m.filtered, e)
		}
	}
	if m.entryIndex >= len(m.filtered) {
		m.entryIndex = max(0, len(m.filtered)-1)
	}
}

func (m model) visibleCatalogGroups() []libraryGroup {
	counts := map[string]int{}
	available := map[string]int{}
	q := strings.ToLower(strings.TrimSpace(m.search))
	seenPaths := map[string]bool{}
	for _, entry := range m.entries {
		if entry.Path != "" {
			if seenPaths[entry.Path] {
				continue
			}
			seenPaths[entry.Path] = true
		}
		if !m.inCurrentFamily(entry) {
			continue
		}
		values := m.groupValues(entry)
		seen := map[string]bool{}
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" || seen[value] || q != "" && !strings.Contains(strings.ToLower(value), q) {
				continue
			}
			seen[value] = true
			counts[value]++
			if !entry.Checked || entry.Available {
				available[value]++
			}
		}
	}
	groups := make([]libraryGroup, 0, len(counts))
	for name, count := range counts {
		groups = append(groups, libraryGroup{Name: name, Count: count, Available: available[name]})
	}
	if m.catalogAxis == "product" {
		sort.Slice(groups, func(i, j int) bool {
			if groups[i].Name == catalog.UnsupportedGroup {
				return false
			}
			if groups[j].Name == catalog.UnsupportedGroup {
				return true
			}
			if groups[i].Name == bruteCategoryLabel || groups[j].Name == bruteCategoryLabel {
				return groups[j].Name == bruteCategoryLabel
			}
			if groups[i].Count == groups[j].Count {
				return groups[i].Name < groups[j].Name
			}
			return groups[i].Count > groups[j].Count
		})
	} else {
		sort.Slice(groups, func(i, j int) bool {
			if groups[i].Name == catalog.UnsupportedGroup {
				return false
			}
			if groups[j].Name == catalog.UnsupportedGroup {
				return true
			}
			if groups[i].Name == bruteCategoryLabel || groups[j].Name == bruteCategoryLabel {
				return groups[j].Name == bruteCategoryLabel
			}
			if m.catalogAxis == "impact" {
				// bruteCategoryLabel sorts last (but still before the
				// Unsupported bucket, which the two early returns above
				// already pin to the very end regardless of rank) — without
				// an explicit entry here it would default to rank 0 via Go's
				// zero-value map lookup, tying with Обнаружение and sorting
				// unpredictably against it under sort.Slice's no stability
				// guarantee.
				rank := map[string]int{
					catalog.ImpactDiscovery: 0, catalog.ImpactActive: 1, catalog.ImpactStrong: 2,
					bruteCategoryLabel: 3,
				}
				return rank[groups[i].Name] < rank[groups[j].Name]
			}
			if m.catalogAxis == "direction" && (groups[i].Name == "Web" || groups[j].Name == "Web") {
				return groups[i].Name == "Web"
			}
			return groups[i].Name < groups[j].Name
		})
	}
	return groups
}

func (m *model) openCatalog(pending bool, back string) {
	m.catalogReadOnly = false
	if pending {
		m.scanReviewReady = false
	}
	m.catalogPending = pending
	m.catalogBack = back
	m.catalogFamily = ""
	m.catalogCategory = ""
	m.catalogProduct = ""
	m.catalogDirection = ""
	m.catalogDatabase = ""
	m.catalogImpact = ""
	m.catalogAxis = "direction"
	m.catalogGroupIndex = 0
	m.search = ""
	if len(m.entries) == 0 {
		m.message = "Библиотека загружается и проверяется…"
		if m.catalogLoadError != "" {
			m.message = m.catalogLoadError
		}
	}

	m.applyFilter()
	if pending && m.actionService != nil {
		for i, g := range m.visibleCatalogGroups() {
			if g.Name == catalog.ServiceDirection(*m.actionService) {
				m.catalogGroupIndex = i
				break
			}
		}
	}
	m.screen = "catalog-groups"
}

func (m *model) toggleScanTemplate(id string) {
	for i, selected := range m.pendingTemplateIDs {
		if selected == id {
			m.pendingTemplateIDs = append(m.pendingTemplateIDs[:i], m.pendingTemplateIDs[i+1:]...)
			return
		}
	}
	m.pendingTemplateIDs = append(m.pendingTemplateIDs, id)
}

func (m *model) setScanTemplateSelection(ids []string, selected bool) {
	set := make(map[string]bool, len(m.pendingTemplateIDs)+len(ids))
	for _, id := range m.pendingTemplateIDs {
		set[id] = true
	}
	for _, id := range ids {
		if selected {
			set[id] = true
		} else {
			delete(set, id)
		}
	}
	m.pendingTemplateIDs = m.pendingTemplateIDs[:0]
	for id := range set {
		m.pendingTemplateIDs = append(m.pendingTemplateIDs, id)
	}
	sort.Strings(m.pendingTemplateIDs)
}

func (m model) pendingNucleiCount() int {
	n := 0
	for _, id := range m.pendingTemplateIDs {
		if !strings.HasPrefix(id, "nmap/scripts/") {
			n++
		}
	}
	return n
}

func (m model) pendingNSECount() int {
	n := 0
	for _, id := range m.pendingTemplateIDs {
		if strings.HasPrefix(id, "nmap/scripts/") {
			n++
		}
	}
	return n
}

func (m model) httpTemplateCount() int {
	n := 0
	for _, id := range m.current.TemplateIDs {
		if !strings.HasPrefix(id, "nmap/scripts/") {
			n++
		}
	}
	return n
}

func (m model) nseTemplateCount() int {
	n := 0
	for _, id := range m.current.TemplateIDs {
		if strings.HasPrefix(id, "nmap/scripts/") {
			n++
		}
	}
	return n
}

// --- misc helpers --------------------------------------------------------

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }

func serviceLabel(s domain.Service) string {
	name := strings.TrimSpace(strings.Join([]string{s.Name, s.Product, s.Version}, " "))
	protocolName := strings.ToLower(strings.TrimSpace(s.Name))
	if s.PortService != "" && (protocolName == "" || protocolName == "unknown" || protocolName == "tcp" || protocolName == "udp") {
		name = strings.TrimSpace(strings.Join([]string{s.PortService, "(по порту)", s.Product, s.Version}, " "))
	}
	if name == "" {
		name = "не определён"
	}
	return fmt.Sprintf("%d/%s  %s", s.Port, s.Protocol, name)
}

func isHTTPService(s domain.Service) bool {
	name := strings.ToLower(s.Name + " " + s.Product + " " + s.Tunnel)
	return strings.Contains(name, "http") || s.Port == 80 || s.Port == 443 || s.Port == 8080 || s.Port == 8443 || s.Port == 8000 || s.Port == 3000
}

func (m model) export(run domain.Run) error {
	if err := os.MkdirAll(filepath.Join(m.appDir, "reports"), 0700); err != nil {
		return err
	}
	data := report.Data{Project: m.current.Name, Run: run}
	for _, format := range []string{"json", "html", "csv"} {
		path := filepath.Join(m.appDir, "reports", fmt.Sprintf("project-%d-run-%d.%s", m.current.ID, run.ID, format))
		if err := report.Export(path, format, data); err != nil {
			return err
		}
	}
	return nil
}

var rowStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#D7E2E0"))
var selectedRowStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#102A2A")).Background(lipgloss.Color("#5EEAD4"))

func renderListRow(text string, selected bool, terminalWidth int) string {
	return renderStyledListRow(text, selected, terminalWidth, rowStyle, selectedRowStyle)
}

func renderStyledListRow(text string, selected bool, terminalWidth int, normal, highlight lipgloss.Style) string {
	if terminalWidth <= 0 {
		terminalWidth = 80
	}
	rowWidth := max(1, terminalWidth-4)
	contentWidth := max(0, rowWidth-2)
	prefix := "  "
	style := normal
	if selected {
		prefix = "▶ "
		style = highlight
	}
	content := ansi.Truncate(prefix+singleLineText(text), contentWidth, "…")
	// Pad to the exact target width ourselves and skip Style.Width(): lipgloss's
	// own reflow measures "▶" as wider than ansi.StringWidth does, so asking it
	// to wrap at a width we already truncated to can fold the last cell of an
	// exactly-fitting row onto a spurious second line.
	if pad := contentWidth - ansi.StringWidth(content); pad > 0 {
		content += strings.Repeat(" ", pad)
	}
	return style.Padding(0, 1).Render(content) + "\n"
}

// Labels are one terminal row. Service-provided names must not inject extra
// rows or terminal controls into every list that uses this renderer.
func singleLineText(text string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, ansi.Strip(text))
}
