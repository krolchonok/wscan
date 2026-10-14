package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/adscan"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

var adAccessModes = []struct{ id, name string }{
	{"coercion-discovery", "Coerce: проверить доступность RPC-интерфейсов машин TCP/445"},
	{"coercion", "Coerce: машины TCP/445 → локальный SMB-приёмник (5 RPC-методов)"},
	{"directory", "LDAP-аудит: учётки, политики, delegation, trusts, LAPS, gMSA, AD CS"},
	{"passpolicy", "Парольная политика и PSO: полный разбор параметров"},
	{"windows", "Windows через WinRM: WDigest, политика, патчи, NIC/routes, firewall, DNS"},
	{"dns", "DNS: анонимный AXFR и объявленная рекурсия"},
	{"asrep", "AS-REP без пароля → Hashcat"},
	{"sysvol", "SYSVOL / NETLOGON: обнаружение устаревших GPP cpassword (без чтения паролей)"},
	{"ldap-security", "LDAP signing / LDAPS channel binding: проба с выбранной учёткой"},
	{"bloodhound-ce", "BloodHound CE: удалённый сбор домена → ZIP (LDAP, без агента)"},
	{"kerberoast", "Kerberoasting: учётка / без pre-auth / готовый TGT → Hashcat"},
	{"ldap-anonymous", "LDAP RootDSE: анонимное определение домена и контроллера"},
	{"sysvol-auth", "SYSVOL / NETLOGON: проверка GPP с выбранной учёткой"},
}

func anonymousADMode(mode string) bool {
	return mode == "dns" || mode == "asrep" || mode == "sysvol" || mode == "ldap-anonymous"
}

func adCheckIndices() []int {
	var indices []int
	for _, anonymous := range []bool{true, false} {
		for i, mode := range adAccessModes {
			if i >= 2 && anonymousADMode(mode.id) == anonymous {
				indices = append(indices, i)
			}
		}
	}
	return indices
}

func nextADCheck(current, delta int) int {
	indices := adCheckIndices()
	for i, index := range indices {
		if index == current {
			return indices[min(len(indices)-1, max(0, i+delta))]
		}
	}
	return indices[0]
}

func (m *model) openADAccess() {
	m.adAccessReturn = m.screen
	m.adAccessHost, m.adAccessDomain = "", ""
	m.adAccessIndex, m.adAccessCred = 2, -1
	m.adBloodHoundPort, m.adBloodHoundLimit = 636, 5000
	m.adAccessLDAPPort = 636
	m.adWindowsPort = 5985
	m.adKerberoastSPNs = ""
	m.adKerberoastAuth = 0
	m.adKerberoastEtypes = 0
	m.adKerberoastNoPreauthUser, m.adKerberoastTGTFile = "", ""
	m.adAccessGeneration++
	m.adAccessAutoBusy, m.adAccessHint = false, ""
	m.adAccessAutoHost = ""
	m.loadADControllerSelection()
	m.prefillADAccessIdentity()
	creds, err := m.store.ListCredentials(m.ctx, m.current.ID)
	if err == nil {
		m.adAccessCreds = creds
	} else {
		m.adAccessCreds = nil
		m.message = "Не удалось загрузить учётки: " + err.Error()
	}
	m.screen = "ad-access"
}

func (m model) updateADAccess(key string) (tea.Model, tea.Cmd) {
	if key == "p" && !m.adAccessJobRunning() {
		return m.toggleResponder()
	}
	if m.adAccessJobRunning() {
		if key == "esc" || key == "q" {
			if j := m.jobByID(m.adAccessJobID); j != nil && j.cancel != nil {
				j.cancel()
			}
			m.message = "Останавливаю AD-проверку…"
		}
		return m, nil
	}
	switch key {
	case "esc", "q":
		m.screen = m.adAccessReturn
		m.message = ""
	case "up", "k":
		m.adAccessIndex = nextADCheck(m.adAccessIndex, -1)
	case "down", "j":
		m.adAccessIndex = nextADCheck(m.adAccessIndex, 1)
	case "v":
		return m.toggleResponderDebug()
	case "l":
		mode := adAccessModes[m.adAccessIndex].id
		if mode == "windows" {
			if m.adWindowsPort == 5986 {
				m.adWindowsPort = 5985
			} else {
				m.adWindowsPort = 5986
			}
		}
		if mode == "directory" || mode == "passpolicy" || mode == "ldap-security" || mode == "kerberoast" || mode == "ldap-anonymous" {
			if m.adAccessLDAPPort == 389 {
				m.adAccessLDAPPort = 636
			} else {
				m.adAccessLDAPPort = 389
			}
		}
		if mode == "bloodhound-ce" {
			if m.adBloodHoundPort == 389 {
				m.adBloodHoundPort = 636
			} else {
				m.adBloodHoundPort = 389
			}
		}
	case "n":
		if adAccessModes[m.adAccessIndex].id == "bloodhound-ce" {
			m.startInput("ad-bloodhound-limit")
		}
	case "s":
		if adAccessModes[m.adAccessIndex].id == "kerberoast" {
			m.startInput("kerberoast-spns")
			m.input = m.adKerberoastSPNs
		}
	case "h":
		m.openADControllerPicker()
	case "a":
		if adAccessModes[m.adAccessIndex].id == "kerberoast" {
			m.adKerberoastAuth = (m.adKerberoastAuth + 1) % 3
		}
	case "u":
		if adAccessModes[m.adAccessIndex].id == "kerberoast" && m.adKerberoastAuth == 1 {
			m.startInput("kerberoast-nopreauth-user")
			m.input = m.adKerberoastNoPreauthUser
		}
	case "e":
		if adAccessModes[m.adAccessIndex].id == "kerberoast" {
			m.adKerberoastEtypes = (m.adKerberoastEtypes + 1) % 3
		}
	case "t":
		if adAccessModes[m.adAccessIndex].id == "kerberoast" && m.adKerberoastAuth == 2 {
			m.startInput("kerberoast-tgt-file")
			m.input = m.adKerberoastTGTFile
		}
	case "r":
		m.startInput("ad-coerce-callback")
	case "d":
		m.openADDomainPicker()
	case "c":
		if len(m.adAccessCreds) == 0 {
			m.message = "В проекте нет сохранённых учёток; нажми c в окне Credentials, затем вернись сюда"
		} else {
			m.adAccessCred++
			if m.adAccessCred >= len(m.adAccessCreds) {
				m.adAccessCred = -1
				m.message = "Учётка не выбрана (anonymous)"
			} else {
				m.message = "Учётка: " + credIdentLabel(m.adAccessCreds[m.adAccessCred])
				if m.screen == "coerce-setup" {
					m.adAccessDomain = m.adAccessCreds[m.adAccessCred].Domain
				}
			}
		}
	case "enter":
		if m.adAccessAutoBusy {
			m.message = "Определяю домен…"
			return m, nil
		}
		if adAccessModes[m.adAccessIndex].id == "asrep" {
			m.openASREPSetup()
			return m, nil
		}
		return m.startADAccess()
	}
	return m, nil
}

func (m model) adAccessJobRunning() bool {
	j := m.jobByID(m.adAccessJobID)
	return j != nil && j.status == statusRunning
}

func (m model) viewADAccess(w int) string {
	body := headingStyle.Render("Проверки AD") + "\n\n"
	cred := "не выбрана"
	if m.adAccessCred >= 0 && m.adAccessCred < len(m.adAccessCreds) {
		cred = credIdentLabel(m.adAccessCreds[m.adAccessCred])
	}
	if anonymousADMode(adAccessModes[m.adAccessIndex].id) {
		cred = "не используется — проверка без учётки"
	}
	domainLabel := valueOr(m.adAccessDomain, "не задан")
	if m.adAccessAutoBusy && m.adAccessDomain == "" {
		domainLabel = "определяется…"
	}
	body += fmt.Sprintf("Контроллер: %s · h выбрать из машин\nДомен: %s · d изменить\nУчётка: %s · c выбрать сохранённую\n", valueOr(m.adAccessHost, "не задан"), domainLabel, cred)
	if m.adAccessHint != "" {
		body += m.adAccessHint + "\n"
	}
	body += "\n"
	if strings.HasPrefix(adAccessModes[m.adAccessIndex].id, "coercion") {
		scope := "выбранные машины с 445, иначе все с 445; h — один хост"
		if m.adAccessHost != "" {
			scope = "только " + m.adAccessHost + "; h — изменить"
		}
		body += fmt.Sprintf("Приёмник: %s:445 · r изменить\nЦели Coerce: %d · %s\n\n", valueOr(m.adCoerceCallback, "не задан"), len(m.coercionTargets()), scope)
	}
	if adAccessModes[m.adAccessIndex].id == "bloodhound-ce" {
		port, limit := m.bloodHoundSettings()
		body += fmt.Sprintf("BloodHound CE · LDAP/%d (l) · лимит объектов/членов группы: %d (n)\n", port, limit)
		body += "Область: выбранный домен; рабочие станции не опрашиваются.\nЭкспорт: " + filepath.Join(m.appDir, "exports", "bloodhound") + "\n"
		body += "Не собираются: ACL, AD CS, сессии и локальные права.\n\n"
	}
	body += "↑/↓ выбрать проверку · Enter запустить · Esc назад\n\n"
	if adAccessModes[m.adAccessIndex].id == "windows" {
		body += fmt.Sprintf("WinRM/%d · l сменить HTTP/HTTPS\n\n", m.adWindowsPort)
	} else if adAccessModes[m.adAccessIndex].id == "directory" || adAccessModes[m.adAccessIndex].id == "passpolicy" || adAccessModes[m.adAccessIndex].id == "ldap-anonymous" || (adAccessModes[m.adAccessIndex].id == "kerberoast" && m.adKerberoastAuth == 0) {
		body += fmt.Sprintf("LDAP/%d · l сменить порт\n\n", m.adAccessLDAPPort)
	}
	if adAccessModes[m.adAccessIndex].id == "kerberoast" {
		modes := []string{"Пароль / NT-хеш", "Без пароля: учётка без pre-auth", "Готовый TGT"}
		auto := "Авто: AES → RC4"
		if m.adKerberoastAuth == 1 {
			auto = "Авто: RC4 → AES"
		}
		body += "a Режим: " + modes[m.adKerberoastAuth] + " · e Шифрование: " + []string{auto, "Только RC4", "Только AES"}[m.adKerberoastEtypes] + "\n"
		if m.adKerberoastAuth == 1 {
			body += "u Логин: " + valueOr(m.adKerberoastNoPreauthUser, "не задан") + " · "
		} else if m.adKerberoastAuth == 2 {
			body += "t Файл TGT: " + valueOr(m.adKerberoastTGTFile, "не задан") + " · "
		}
		spns := "активные пользовательские SPN из LDAP"
		if m.adKerberoastAuth != 0 {
			spns = "укажи SPN или @файл"
		}
		body += "s SPN: " + valueOr(m.adKerberoastSPNs, spns) + "\n"
		if m.adKerberoastAuth != 0 {
			body += "Для AES: SPN|логин владельца; RC4 — SPN\n"
		}
		body += "\n"
	}

	group := ""
	var menuLines []string
	selectedLine := 0
	for _, i := range adCheckIndices() {
		row := adAccessModes[i]
		heading := "Нужна учётка / билет"
		if anonymousADMode(row.id) {
			heading = "Без учётки (анонимно)"
		}
		if heading != group {
			menuLines = append(menuLines, heading)
			group = heading
		}
		if i == m.adAccessIndex {
			selectedLine = len(menuLines)
		}
		menuLines = append(menuLines, strings.TrimSuffix(renderListRow(row.name, i == m.adAccessIndex, w), "\n"))
	}
	rows := max(1, m.bodyHeight()-2-strings.Count(body, "\n"))
	start := min(max(0, selectedLine-rows+1), max(0, len(menuLines)-rows))
	body += strings.Join(menuLines[start:min(len(menuLines), start+rows)], "\n")
	if m.adAccessJobRunning() {
		body += "\n\nВыполняется проверка… Esc — отменить"
	}
	return m.renderPanel(w, body)
}
func valueOr(v, empty string) string {
	if strings.TrimSpace(v) == "" {
		return empty
	}
	return v
}

func (m model) startADAccess() (tea.Model, tea.Cmd) {
	if m.adAccessAutoBusy {
		m.message = "Определяю домен…"
		return m, nil
	}
	if m.current.ID == 0 {
		m.message = "Сначала открой проект"
		return m, nil
	}
	if strings.HasPrefix(adAccessModes[m.adAccessIndex].id, "coercion") {
		return m.startCoercion()
	}
	if adAccessModes[m.adAccessIndex].id == "asrep" {
		return m.startASREP()
	}
	if strings.TrimSpace(m.adAccessHost) == "" || (strings.TrimSpace(m.adAccessDomain) == "" && adAccessModes[m.adAccessIndex].id != "windows" && adAccessModes[m.adAccessIndex].id != "ldap-anonymous") {
		m.message = "Укажи хост контроллера (h) и домен (d)"
		return m, nil
	}
	mode := adAccessModes[m.adAccessIndex].id
	var cred domain.Credential
	if m.adAccessCred >= 0 && m.adAccessCred < len(m.adAccessCreds) {
		cred = m.adAccessCreds[m.adAccessCred]
	}
	if anonymousADMode(mode) {
		cred = domain.Credential{}
	} else if mode != "kerberoast" && cred.Username == "" {
		m.message = "Выбери сохранённую учётку (c) для этой проверки. Без учётки доступны LDAP RootDSE, DNS, AS-REP и SYSVOL."
		return m, nil
	}
	port := m.adAccessLDAPPort
	if port != 389 && port != 636 {
		port = 636
	}
	o := adscan.AccessOptions{Host: strings.TrimSpace(m.adAccessHost), Domain: strings.TrimSpace(m.adAccessDomain), Mode: mode, Credential: cred, LDAPPort: port, MaxObjects: 5000, ExportDir: filepath.Join(m.appDir, "exports", "ad")}
	if mode == "windows" {
		if cred.Username == "" {
			m.message = "Выбери известную учётку (c) для WinRM"
			return m, nil
		}
		o.WinRMPort = m.adWindowsPort
		o.Timeout = 30 * time.Second
	}
	if mode == "kerberoast" {
		var err error
		o, err = m.kerberoastOptions()
		if err != nil {
			m.message = err.Error()
			return m, nil
		}
	}
	if mode == "bloodhound-ce" {
		if cred.Username == "" {
			m.message = "Выбери доменную учётку (c): BloodHound не собирается анонимно"
			return m, nil
		}
		o.LDAPPort, o.MaxObjects = m.bloodHoundSettings()
		o.ExportDir = filepath.Join(m.appDir, "exports", "bloodhound")
	}
	worker := m
	m.adAccessJobID = m.jobSeq + 1
	m.message = ""
	m.launch("ad-access", "AD "+mode+" · "+o.Host, []string{o.Host}, worker.runADAccess(o))
	m.openADJob(adscan.AccessDiagnostics(o)...)
	return m, nil
}

func (m *model) openADJob(options ...string) {
	m.adAccessJobID = m.jobSeq
	for i, j := range m.jobs {
		if j.id == m.adAccessJobID {
			j.scope = strings.Join(j.targets, ", ")
			j.checks = []string{j.label}
			j.options = append(j.options, options...)
			m.initJobLog(j)
			m.jobIndex = i
			m.jobDetailRaw, m.jobDetailErrors, m.logOffset = true, false, -1
			m.screen = "job-details"
			return
		}
	}
}

func (m model) runADAccess(o adscan.AccessOptions) runFunc {
	if o.Mode == "asrep" {
		return m.runASREP(o)
	}
	return func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		emit("AD " + o.Mode + ": " + o.Host)
		for _, option := range adscan.AccessDiagnostics(o) {
			emit(option)
		}
		runID, err := m.store.StartRun(ctx, m.current.ID)
		if err != nil {
			return engine.Result{}, err
		}
		status := "completed"
		defer func() { _ = m.store.FinishRun(context.Background(), runID, status) }()
		var report adscan.AccessReport
		if o.Mode == "bloodhound-ce" {
			report, err = adscan.RunBloodHound(ctx, adscan.BloodHoundOptions{AccessOptions: o, Progress: func(s string) { emit(s) }})
		} else {
			o.Progress = func(s string) { emit(s) }
			report, err = adscan.RunAccess(ctx, o)
		}
		runErr := err
		for _, policy := range report.Policies {
			m.scanner.RememberLocalPolicy(m.current.ID, policy)
		}
		if runErr != nil {
			status = "failed"
			if ctx.Err() != nil {
				status = "cancelled"
			}
			report.Checks = append(report.Checks, adscan.AccessCheck{ID: "execution", Name: "Выполнение проверки", State: "error", Severity: "info", Evidence: runErr.Error()})
		}
		saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer saveCancel()
		if len(report.Artifacts) > 0 {
			report.Checks = append(report.Checks, adscan.AccessCheck{ID: "artifacts", Name: "Локальные артефакты", State: "observed", Severity: "info", Evidence: strings.Join(report.Artifacts, "\n")})
		}
		if err = writeADReport(o.ExportDir, &report); err != nil {
			status = "failed"
			return engine.Result{RunID: runID, TargetsScanned: 1, Errors: []string{err.Error()}}, err
		}
		findings := report.Findings()
		for _, f := range findings {
			if err = m.store.SaveFinding(saveCtx, runID, f); err != nil {
				status = "failed"
				return engine.Result{RunID: runID, TargetsScanned: 1, Findings: findings, Errors: []string{err.Error()}}, err
			}
		}
		result := engine.Result{RunID: runID, TargetsScanned: 1, Findings: findings}
		if runErr != nil {
			result.Errors = []string{runErr.Error()}
		}
		for _, check := range report.Checks {
			if check.ID == "execution" {
				continue
			}
			message := check.Name + " [" + check.State + "]: " + check.Evidence
			emit(message)
			if check.State == "error" || check.State == "incomplete" {
				result.Errors = append(result.Errors, message)
			}
		}
		return result, runErr
	}
}

func writeADReport(dir string, r *adscan.AccessReport) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "ad-report-*.json")
	if err != nil {
		return err
	}
	name := f.Name()
	if err = f.Chmod(0600); err == nil {
		err = json.NewEncoder(f).Encode(r)
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		_ = os.Remove(name)
		return err
	}
	r.Artifacts = append(r.Artifacts, name)
	return nil
}

func (m model) coercionTargets() []string {
	if h := strings.TrimSpace(m.adAccessHost); h != "" {
		return []string{h}
	}
	hosts := []string{}
	seen := map[string]bool{}
	selected := false
	for _, v := range m.selectedHosts {
		if v {
			selected = true
			break
		}
	}
	for bucket, info := range m.inventory {
		if selected && !m.selectedHosts[bucket] {
			continue
		}
		for _, service := range info.services {
			if service.Port != 445 || (service.Protocol != "" && service.Protocol != "tcp") || (service.State != "" && service.State != "open") {
				continue
			}
			host := service.Host
			if host == "" {
				host = bucket
			}
			if !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
		}
	}
	sort.Strings(hosts)
	return hosts
}
func (m model) startCoercion() (tea.Model, tea.Cmd) {
	targets := m.coercionTargets()
	if len(targets) == 0 {
		m.message = "Нет машин с открытым TCP/445; выполни поиск портов или укажи один хост (h)"
		return m, nil
	}
	discoverOnly := adAccessModes[m.adAccessIndex].id == "coercion-discovery"
	if !discoverOnly && strings.TrimSpace(m.adCoerceCallback) == "" {
		m.message = "Укажи локальный адрес приёмника (r)"
		return m, nil
	}
	if !discoverOnly && !m.coercePortApproved && !m.responderRunningAtCallback() {
		return m.requestCoercionPort("coercion")
	}
	m.coercePortApproved = false
	var cred domain.Credential
	if m.adAccessCred >= 0 && m.adAccessCred < len(m.adAccessCreds) {
		cred = m.adAccessCreds[m.adAccessCred]
	}
	o := adscan.CoercionOptions{ReceiverDebug: m.responderDebug, DiscoverOnly: discoverOnly, Targets: targets, Callback: strings.TrimSpace(m.adCoerceCallback), Credential: adscan.AccessOptions{Domain: strings.TrimSpace(m.adAccessDomain), Credential: cred}}
	worker := m
	m.adAccessJobID = m.jobSeq + 1
	m.message = ""
	title := fmt.Sprintf("Coerce · %d машин · %s:445", len(targets), o.Callback)
	if discoverOnly {
		title = fmt.Sprintf("Coerce RPC discovery · %d машин", len(targets))
	}
	lease := m.coercePortLease
	m.coercePortLease = nil
	m.launch("ad-access", title, targets, worker.runCoercion(o, lease))
	return m, nil
}
func (m model) runCoercion(o adscan.CoercionOptions, leases ...*adscan.PortLease) runFunc {
	return func(ctx context.Context, emit progressReporter) (output engine.Result, returnedError error) {
		if len(leases) > 0 && leases[0] != nil {
			defer func() {
				if err := leases[0].Restore(); err != nil {
					returnedError = errors.Join(returnedError, fmt.Errorf("восстановление Samba: %w", err))
					output.Errors = append(output.Errors, err.Error())
				}
			}()
		}
		runID, err := m.store.StartRun(ctx, m.current.ID)
		if err != nil {
			return engine.Result{}, err
		}
		status := "completed"
		defer func() { _ = m.store.FinishRun(context.Background(), runID, status) }()
		var reports []adscan.AccessReport
		var scanErr error
		if o.Methods != nil && len(o.Methods) == 1 && o.Methods[0] == "responder" {
			reports, scanErr = adscan.RunResponderWithOptions(ctx, o.Callback, o.Targets, adscan.ResponderOptions{Debug: o.ReceiverDebug}, func(s string) { emit(s) })
		} else {
			reports, scanErr = adscan.RunCoercion(ctx, o, func(s string) { emit(s) })
		}
		result := engine.Result{RunID: runID, TargetsScanned: len(reports)}
		// Persist partial results even when the operator cancels the job.
		saveCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, report := range reports {
			if e := writeADReport(filepath.Join(m.appDir, "exports", "ad"), &report); e != nil {
				result.Errors = append(result.Errors, e.Error())
				status = "failed"
			}
			for _, f := range report.Findings() {
				result.Findings = append(result.Findings, f)
				if e := m.store.SaveFinding(saveCtx, runID, f); e != nil {
					result.Errors = append(result.Errors, e.Error())
					status = "failed"
				}
			}
		}
		if scanErr != nil {
			status = "failed"
			result.Errors = append(result.Errors, scanErr.Error())
		}
		if scanErr == nil && len(result.Errors) > 0 {
			scanErr = fmt.Errorf("ошибки сохранения: %s", strings.Join(result.Errors, "; "))
		}
		return result, scanErr
	}
}

func (m model) responderStatus() string {
	if j := m.jobByID(m.adResponderJobID); j != nil && j.status == statusRunning {
		return j.stage
	}
	return "остановлен"
}
func (m model) toggleResponder() (tea.Model, tea.Cmd) {
	if j := m.jobByID(m.adResponderJobID); j != nil && j.status == statusRunning {
		if j.cancel != nil {
			j.cancel()
		}
		m.message = "Останавливаю Responder; сохраняю события…"
		return m, nil
	}
	if m.current.ID == 0 {
		m.message = "Сначала открой проект"
		return m, nil
	}
	if strings.TrimSpace(m.adCoerceCallback) == "" {
		m.message = "Задай локальный IPv4 приёмника (r)"
		return m, nil
	}
	targets := m.coercionTargets()
	if len(targets) == 0 {
		m.message = "Выбери машины с 445 или укажи один хост (h)"
		return m, nil
	}
	o := adscan.CoercionOptions{ReceiverDebug: m.responderDebug, Targets: targets, Callback: strings.TrimSpace(m.adCoerceCallback), Methods: []string{"responder"}}
	worker := m
	if !m.coercePortApproved {
		return m.requestCoercionPort("responder")
	}
	m.coercePortApproved = false
	m.adResponderJobID = m.jobSeq + 1
	lease := m.coercePortLease
	m.coercePortLease = nil
	m.launch("responder", "Responder · "+o.Callback+":445", targets, worker.runCoercion(o, lease))
	return m, nil
}

func (m model) responderRunningAtCallback() bool {
	if j := m.jobByID(m.adResponderJobID); j != nil && j.status == statusRunning {
		return strings.Contains(j.label, m.adCoerceCallback+":445")
	}
	return false
}

func (m model) bloodHoundSettings() (int, int) {
	port, limit := m.adBloodHoundPort, m.adBloodHoundLimit
	if port != 389 && port != 636 {
		port = 636
	}
	if limit < 1 || limit > 50000 {
		limit = 5000
	}
	return port, limit
}

func (m model) toggleResponderDebug() (tea.Model, tea.Cmd) {
	if j := m.jobByID(m.adResponderJobID); j != nil && j.status == statusRunning {
		m.message = "Для смены диагностики останови Responder и запусти снова"
		return m, nil
	}
	m.responderDebug = !m.responderDebug
	m.message = fmt.Sprintf("Диагностика Responder: %t · подробные события в журнале задачи", m.responderDebug)
	return m, nil
}
