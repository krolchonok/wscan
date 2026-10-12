package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"wscan/internal/adscan"
	"wscan/internal/domain"
	"wscan/internal/engine"
	enginejs "wscan/internal/engine/js"
	"wscan/internal/nse"
)

func (m *model) openADScan() {
	m.adScanReturn = m.screen
	m.adScanNewProject = m.current.ID == 0
	var err error
	m.adNetworks, err = adscan.LocalNetworks()
	m.adNetworkIndex = 0
	m.serviceIndex = 0
	m.adScanDone = 0
	m.adScanTotal = 0
	m.adScanResult = nil
	m.adScanError = ""
	if err != nil {
		m.adScanError = err.Error()
	}
	m.message = ""
	m.screen = "ad-scan"
}

func (m model) updateADScan(key string) (tea.Model, tea.Cmd) {
	if m.adScanRunning {
		switch key {
		case "x", "esc", "q":
			if job := m.jobByID(m.adScanJobID); job != nil && job.cancel != nil {
				job.cancel()
			}
			m.message = "Останавливаю сканирование…"
		}
		return m, nil
	}
	if m.adScanResult != nil && m.adScanError == "" {
		switch key {
		case "up", "k":
			if m.serviceIndex > 0 {
				m.serviceIndex--
			}
			return m, nil
		case "down", "j":
			if m.serviceIndex+1 < len(m.adScanResult.Hosts) {
				m.serviceIndex++
			}
			return m, nil
		}
	}
	switch key {
	case "p":
		if m.current.ID == 0 {
			m.message = "Текущий проект не открыт; результаты будут сохранены в новый проект"
		} else {
			m.adScanNewProject = !m.adScanNewProject
			m.message = ""
		}
	case "up", "k":
		if m.adNetworkIndex > 0 {
			m.adNetworkIndex--
		}
	case "down", "j":
		if m.adNetworkIndex < len(m.adNetworks) {
			m.adNetworkIndex++
		}
	case "r":
		var err error
		m.adNetworks, err = adscan.LocalNetworks()
		m.adNetworkIndex = 0
		m.adScanResult = nil
		m.serviceIndex = 0
		m.adScanError = ""
		if err != nil {
			m.adScanError = err.Error()
		}
	case "esc", "q":
		m.screen = m.adScanReturn
		m.message = ""
	case "enter":
		if m.adNetworkIndex == len(m.adNetworks) {
			m.startInput("ad-cidr")
			return m, nil
		}
		selected := m.adNetworks[m.adNetworkIndex]
		m.adScanRunning = true
		m.adScanDone = 0
		m.adScanTotal = 0
		m.adScanResult = nil
		m.serviceIndex = 0
		m.adScanError = ""
		m.message = ""
		m.launchADScan(selected.CIDR)
	}
	return m, nil
}

func (m *model) launchADScan(cidr string) {
	worker := *m // Capture the destination before the background scan starts.
	m.jobSeq++
	id := m.jobSeq
	ctx, cancel := context.WithCancel(m.ctx)
	j := &job{
		id: id, kind: jobAD,
		label: "AD scan " + cidr, targets: []string{cidr},
		status: statusRunning, stage: "подготовка диапазона…",
		started: time.Now(), cancel: cancel, scope: cidr,
	}
	if !worker.adScanNewProject && worker.current.ID != 0 {
		j.projectID = worker.current.ID
		j.options = []string{"Сохранение: текущий проект " + worker.current.Name}
	} else {
		j.options = []string{"Сохранение: новый проект"}
	}
	m.jobs = append(m.jobs, j)
	m.adScanJobID = id
	m.initJobLog(j)
	ch := m.jobEvents
	go func() {
		result, details, projectID, projectName, err := worker.runADScan(ctx, cidr, func(stage string, counts ...int) {
			ev := jobEvent{id: id, stage: stage, hasProgress: len(counts) == 2}
			if len(counts) == 2 {
				ev.completed, ev.total = counts[0], counts[1]
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
			}
		})
		ch <- jobEvent{id: id, done: true, result: result, adResult: details, projectID: projectID, projectName: projectName, err: err}
	}()
}

// adResultProject adds discovered targets without replacing existing scope or settings.
func (m model) adResultProject(ctx context.Context, cidr string, details adscan.Result) (int64, string, error) {
	targets := []string{cidr}
	for _, node := range details.Hosts {
		targets = append(targets, node.Address)
	}
	targets = uniqueStrings(targets)
	if m.adScanNewProject || m.current.ID == 0 {
		name := adProjectName(cidr, details)
		id, err := m.store.CreateProjectWithTargets(ctx, name, targets)
		return id, name, err
	}
	projects, err := m.store.ListProjects(ctx)
	if err != nil {
		return 0, "", err
	}
	for _, project := range projects {
		if project.ID != m.current.ID {
			continue
		}
		for _, target := range targets {
			if err := m.store.AddTarget(ctx, project.ID, target); err != nil {
				return project.ID, project.Name, fmt.Errorf("не удалось дополнить цели AD-проекта: %w", err)
			}
		}
		return project.ID, project.Name, nil
	}
	return 0, "", fmt.Errorf("выбранный проект больше не существует; новый проект автоматически не создаётся")
}

func (m model) runADScan(ctx context.Context, cidr string, emit progressReporter) (engine.Result, *adscan.Result, int64, string, error) {
	details, err := adscan.Scan(ctx, cidr, func(done, total int) {
		emit("AD-инвентаризация: "+cidr, done, total)
	})
	if err != nil {
		return engine.Result{}, &details, 0, "", err
	}
	if err := enumerateAnonymousSMB(ctx, &details, func(host string) {
		emit("Проверяю анонимный SMB: " + host)
	}); err != nil {
		return engine.Result{}, &details, 0, "", err
	}
	emit("Запрашиваю AD DNS SRV-записи у найденных DNS-серверов…")
	var dnsErrors []string
	details.DNSRecords, dnsErrors, err = adscan.LookupADSRV(ctx, details.Hosts)
	if err != nil {
		return engine.Result{}, &details, 0, "", err
	}
	for _, dnsErr := range dnsErrors {
		emit("DNS SRV: " + dnsErr)
	}
	emit("Сохраняю AD-инвентаризацию в выбранный проект…")
	projectID, projectName, err := m.adResultProject(ctx, cidr, details)
	if err != nil {
		return engine.Result{}, &details, projectID, projectName, err
	}
	runID, err := m.store.StartRun(ctx, projectID)
	if err != nil {
		return engine.Result{}, &details, projectID, projectName, fmt.Errorf("не удалось начать запись AD-запуска в выбранном проекте: %w", err)
	}
	status := "completed"
	defer func() {
		_ = m.store.FinishRun(context.Background(), runID, status)
	}()
	result := engine.Result{RunID: runID, TargetsScanned: 1, Errors: append([]string(nil), dnsErrors...)}
	result.TargetsScanned = details.HostsScanned
	if len(details.Hosts) > 0 {
		result.HostNames = make(map[string][]string)
	}
	for _, node := range details.Hosts {
		if node.LDAPMessage != "" {
			emit("LDAP · " + node.Address + " · " + node.LDAPMessage)
		}
		if node.HostName != "" {
			result.HostNames[node.Address] = []string{node.HostName}
		}
	}
	if len(result.HostNames) > 0 {
		if err := m.store.SaveHostNames(ctx, projectID, result.HostNames); err != nil {
			status = "failed"
			return result, &details, projectID, projectName, fmt.Errorf("не удалось сохранить имена AD-хостов: %w", err)
		}
	}
	for _, node := range details.Hosts {
		for _, port := range node.Ports {
			name, portService := adPortNames(port)
			product := ""
			if node.Domain != "" && (port == 389 || port == 636 || port == 3268 || port == 3269 || port == 88 || port == 464 || port == 9389) {
				product = "Active Directory"
			}
			if roleContains(node.Roles, "AD CS") && (port == 80 || port == 443) {
				product = "Microsoft AD CS"
			}
			service := domain.Service{
				State: "open", Host: node.Address, Port: port, Protocol: "tcp",
				Name: name, PortService: portService, Product: product, Target: node.Address,
			}
			if err := m.store.SaveService(ctx, runID, service); err != nil {
				status = "failed"
				return result, &details, projectID, projectName, err
			}
			result.Services = append(result.Services, service)
		}
		for _, role := range node.Roles {
			description := role + " обнаружен по сетевым признакам."
			if role == "AD CS" {
				var endpoints []string
				for _, endpoint := range node.ADCSPaths {
					endpoints = append(endpoints, fmt.Sprintf("TCP/%d%s", endpoint.Port, endpoint.Path))
				}
				if len(endpoints) > 0 {
					description += " Endpoints: " + strings.Join(endpoints, ", ") + "."
				}
			}
			finding := domain.Finding{
				Description: description, Evidence: description, MatcherName: "ad-role-" + adRoleKey(role), Protocol: "ad",
				TemplateID: "adscan-role-" + adRoleKey(role), Name: role, Severity: "info",
				Target: cidr, MatchedAt: node.Address, Risk: "Роль определена пассивной проверкой доступных AD-служб.", Time: time.Now().UTC(),
			}
			if err := m.store.SaveFinding(ctx, runID, finding); err != nil {
				status = "failed"
				return result, &details, projectID, projectName, err
			}
			result.Findings = append(result.Findings, finding)
		}
		if node.Domain != "" || node.HostName != "" || node.LDAPMessage != "" {
			description := "Анонимный LDAP RootDSE"
			if node.LDAPMessage != "" {
				description += "; " + node.LDAPMessage
			}
			if node.Domain != "" {
				description += "; домен: " + node.Domain
			}
			if node.HostName != "" {
				description += "; имя контроллера: " + node.HostName
			}
			finding := domain.Finding{
				Description: description, MatcherName: "anonymous-rootdse", Protocol: "ldap",
				TemplateID: "adscan-rootdse", Name: "Сведения Active Directory из RootDSE",
				Severity: "info", Target: cidr, MatchedAt: node.Address,
				Evidence: description,
				Risk:     "Анонимная проверка RootDSE; отсутствие данных не означает отсутствия AD.",
				Time:     time.Now().UTC(),
			}
			if err := m.store.SaveFinding(ctx, runID, finding); err != nil {
				status = "failed"
				return result, &details, projectID, projectName, err
			}
			result.Findings = append(result.Findings, finding)
		}
		if len(node.LDAPUsers) > 0 {
			finding := adEvidenceFinding(cidr, node.Address, "ldap-anonymous-users", "Анонимное перечисление пользователей LDAP", accountSample(node.LDAPUsers), "Анонимный LDAP-запрос вернул учётные записи домена.")
			if err := m.store.SaveFinding(ctx, runID, finding); err != nil {
				status = "failed"
				return result, &details, projectID, projectName, err
			}
			result.Findings = append(result.Findings, finding)
		}
		if len(node.ASREPUsers) > 0 {
			finding := adEvidenceFinding(cidr, node.Address, "asrep-candidates", "Учётные записи без Kerberos pre-auth", accountSample(node.ASREPUsers), "Эти учётные записи допускают проверку AS-REP Roasting. Сканер сохраняет только имена и не запрашивает хеши.")
			if err := m.store.SaveFinding(ctx, runID, finding); err != nil {
				status = "failed"
				return result, &details, projectID, projectName, err
			}
			result.Findings = append(result.Findings, finding)
		}
		if len(node.SPNUsers) > 0 {
			finding := adEvidenceFinding(cidr, node.Address, "spn-account-candidates", "Учётные записи со SPN", accountSample(node.SPNUsers), "Для Kerberoasting требуется доменная учётная запись; хеши не запрашиваются.")
			if err := m.store.SaveFinding(ctx, runID, finding); err != nil {
				status = "failed"
				return result, &details, projectID, projectName, err
			}
			result.Findings = append(result.Findings, finding)
		}
		ldapPosture := []struct {
			key, name, evidence, risk string
			accounts                  []string
		}{
			{"password-not-required", "Учётки с флагом PASSWD_NOTREQD", "Анонимный LDAP вернул включённые учётки с флагом PASSWD_NOTREQD: " + accountSample(node.PasswordNotRequiredUsers), "Флаг указывает, что AD не требует пароль при изменении пароля через некоторые интерфейсы; это не означает, что пустой пароль подходит для входа.", node.PasswordNotRequiredUsers},
			{"password-never-expires", "Учётки без срока действия пароля", "Анонимный LDAP вернул включённые учётки с флагом DONT_EXPIRE_PASSWORD: " + accountSample(node.PasswordNeverExpiresUsers), "Проверьте владельцев и необходимость исключения из ротации; сканер не проверяет пароли.", node.PasswordNeverExpiresUsers},
			{"unconstrained-delegation", "Учётки с unconstrained delegation", "Анонимный LDAP вернул включённые учётки с unconstrained delegation: " + accountSample(node.DelegationUsers), "Делегирование повышает последствия компрометации этих учёток; перепроверьте настройку и исключения.", node.DelegationUsers},
			{"reversible-encryption", "Учётки с обратимым хранением пароля", "Анонимный LDAP вернул включённые учётки с флагом ENCRYPTED_TEXT_PWD_ALLOWED: " + accountSample(node.ReversibleEncryptionUsers), "Настройка допускает хранение пароля в форме, обратимой для совместимости; проверьте, нужна ли она.", node.ReversibleEncryptionUsers},
			{"des-only-kerberos", "Учётки с DES-only Kerberos", "Анонимный LDAP вернул включённые учётки с флагом USE_DES_KEY_ONLY: " + accountSample(node.DESOnlyUsers), "DES считается устаревшим шифром; проверьте совместимость и отключите его, если он больше не нужен.", node.DESOnlyUsers},
			{"admincount", "Учётки с adminCount=1", "Анонимный LDAP вернул включённые учётки с adminCount=1: " + accountSample(node.AdminCountUsers), "Атрибут может остаться от членства в защищённой группе и сам по себе не доказывает текущие административные права.", node.AdminCountUsers},
		}
		for _, check := range ldapPosture {
			if len(check.accounts) == 0 {
				continue
			}
			finding := adEvidenceFinding(cidr, node.Address, check.key, check.name, check.evidence, check.risk)
			if err := m.store.SaveFinding(ctx, runID, finding); err != nil {
				status = "failed"
				return result, &details, projectID, projectName, err
			}
			result.Findings = append(result.Findings, finding)
		}
		if node.SMBNull || node.SMBGuest {
			var access []string
			if node.SMBNull {
				access = append(access, "null session: "+strings.Join(node.NullShares, ", "))
			}
			if node.SMBGuest {
				access = append(access, "guest: "+strings.Join(node.GuestShares, ", "))
			}
			finding := adEvidenceFinding(cidr, node.Address, "smb-anonymous-access", "SMB доступен без пользовательской учётки", strings.Join(access, "; "), "Проверено только перечисление имён общих папок; содержимое файлов не читается.")
			if err := m.store.SaveFinding(ctx, runID, finding); err != nil {
				status = "failed"
				return result, &details, projectID, projectName, err
			}
			result.Findings = append(result.Findings, finding)
		}
	}
	for _, finding := range adDNSFindings(cidr, details.DNSRecords) {
		if err := m.store.SaveFinding(ctx, runID, finding); err != nil {
			status = "failed"
			return result, &details, projectID, projectName, err
		}
		result.Findings = append(result.Findings, finding)
	}
	checks, checkErrors := m.runADNSEChecks(ctx, details.Hosts, emit)
	if ctx.Err() != nil {
		status = "cancelled"
		return result, &details, projectID, projectName, ctx.Err()
	}
	result.Errors = append(result.Errors, checkErrors...)
	for _, scanErr := range checkErrors {
		emit("Некоторые SMB/RDP-проверки завершились с ошибкой: " + scanErr)
	}
	for _, finding := range checks {
		if err := m.store.SaveFinding(ctx, runID, finding); err != nil {
			status = "failed"
			return result, &details, projectID, projectName, err
		}
		result.Findings = append(result.Findings, finding)
	}
	summary := adReconSummary(cidr, details, result.Findings)
	if err := m.store.SaveFinding(ctx, runID, summary); err != nil {
		status = "failed"
		return result, &details, projectID, projectName, err
	}
	result.Findings = append(result.Findings, summary)
	return result, &details, projectID, projectName, nil
}

func adDNSFindings(cidr string, records []adscan.SRVRecord) []domain.Finding {
	byServer := map[string][]string{}
	for _, record := range records {
		byServer[record.Server] = append(byServer[record.Server], fmt.Sprintf("%s → %s:%d (priority %d, weight %d)", record.Query, record.Target, record.Port, record.Priority, record.Weight))
	}
	servers := make([]string, 0, len(byServer))
	for server := range byServer {
		servers = append(servers, server)
	}
	sort.Strings(servers)
	out := make([]domain.Finding, 0, len(servers))
	for _, server := range servers {
		lines := uniqueStrings(byServer[server])
		sort.Strings(lines)
		out = append(out, adEvidenceFinding(cidr, server, "dns-srv", "AD DNS SRV-инвентаризация", strings.Join(lines, "\n"), "Запрошены только стандартные LDAP/Kerberos/GC SRV-записи; адреса из ответов не сканируются автоматически."))
	}
	return out
}

func adReconSummary(cidr string, result adscan.Result, findings []domain.Finding) domain.Finding {
	var dc, gc, dns, adcs, smbAnonymous int
	users, asrep, spn := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var domains, controllers, ldapStatuses []string
	for _, host := range result.Hosts {
		if host.Domain != "" {
			domains = append(domains, host.Domain)
		}
		if host.LDAPMessage != "" {
			ldapStatuses = append(ldapStatuses, host.Address+": "+host.LDAPMessage)
		}
		if roleContains(host.Roles, "Контроллер домена") {
			controllers = append(controllers, host.Address+" "+host.HostName)
			dc++
		}
		if roleContains(host.Roles, "Global Catalog") {
			gc++
		}
		if roleContains(host.Roles, "DNS") {
			dns++
		}
		if roleContains(host.Roles, "AD CS") {
			adcs++
		}
		if host.SMBNull || host.SMBGuest {
			smbAnonymous++
		}
		for _, name := range host.LDAPUsers {
			users[name] = true
		}
		for _, name := range host.ASREPUsers {
			asrep[name] = true
		}
		for _, name := range host.SPNUsers {
			spn[name] = true
		}
	}
	ms17010, risks := 0, 0
	for _, finding := range findings {
		if finding.Severity == "unknown" {
			risks++
			if strings.Contains(finding.TemplateID, "smb-vuln-ms17-010") {
				ms17010++
			}
		}
	}
	priority := "Дальше изучите найденные узлы и доступы в проекте."
	if ms17010 > 0 {
		priority = "Высший приоритет: вручную перепроверьте MS17-010 на указанных SMB-узлах."
	} else if smbAnonymous > 0 {
		priority = "Приоритет: проверьте анонимно доступные SMB-ресурсы и связанные учётки."
	} else if len(asrep) > 0 || len(spn) > 0 {
		priority = "Приоритет: разберите найденные кандидаты учёток и параметры Kerberos."
	}
	evidence := fmt.Sprintf("Узлы с AD/Windows-службами: %d из %d адресов; DC: %d; Global Catalog: %d; DNS: %d; AD CS: %d; анонимные SMB: %d; LDAP-учётки: %d; AS-REP кандидаты: %d; SPN-кандидаты: %d; SRV-записи: %d; риск-находки: %d. %s",
		len(result.Hosts), result.HostsScanned, dc, gc, dns, adcs, smbAnonymous, len(users), len(asrep), len(spn), len(result.DNSRecords), risks, priority)
	if len(domains) > 0 {
		evidence += "\nДомены: " + strings.Join(uniqueStrings(domains), ", ")
	}
	if len(controllers) > 0 {
		evidence += "\nКонтроллеры: " + strings.Join(controllers, ", ")
	}
	if len(ldapStatuses) > 0 {
		evidence += "\nLDAP:\n" + strings.Join(ldapStatuses, "\n")
	}
	return adEvidenceFinding(cidr, cidr, "recon-summary", "Сводка первичной AD-разведки", evidence, "Краткая навигация по результатам этого этапа; выводы по учёткам и уязвимостям нужно перепроверять перед дальнейшей работой.")
}

// runADNSEChecks runs a fixed allowlist of safe, unauthenticated SMB/RDP
// discovery checks. The vulnerability probe is Nmap's safe MS17-010 check;
// no exploit payload is sent.
func (m model) runADNSEChecks(ctx context.Context, hosts []adscan.Host, emit progressReporter) ([]domain.Finding, []string) {
	runner := nse.New(m.cat.LibraryDir(), nse.Config{
		Timeout: 3 * time.Second, ScriptTimeout: 10 * time.Second,
		RPS: 4, SelectedServicesOnly: true,
	})
	var findings []domain.Finding
	var errs []string
	for _, host := range hosts {
		if ctx.Err() != nil {
			return findings, append(errs, ctx.Err().Error())
		}
		var scripts []string
		if containsInt(host.Ports, 139) || containsInt(host.Ports, 445) {
			scripts = append(scripts,
				"nmap/scripts/smb-protocols.nse",
				"nmap/scripts/smb-security-mode.nse",
				"nmap/scripts/smb-os-discovery.nse",
				"nmap/scripts/smb-vuln-ms17-010.nse",
			)
		}
		if containsInt(host.Ports, 3389) {
			scripts = append(scripts, "nmap/scripts/rdp-ntlm-info.nse")
		}
		if len(scripts) == 0 {
			continue
		}
		ports := make([]nse.PortInfo, 0, len(host.Ports))
		for _, port := range host.Ports {
			service, name := adPortNames(port)
			ports = append(ports, nse.PortInfo{Number: port, Protocol: "tcp", State: "open", Service: service, Product: name})
		}
		for _, id := range scripts {
			if ctx.Err() != nil {
				return findings, append(errs, ctx.Err().Error())
			}
			if emit != nil {
				emit("Анонимная проверка: " + host.Address + " · " + filepath.Base(id))
			}
			path := filepath.Join(m.cat.LibraryDir(), filepath.FromSlash(id))
			results, ran, err := runner.Run(ctx, path, nse.HostInfo{IP: host.Address}, ports)
			if err != nil {
				errs = append(errs, id+": "+err.Error())
			}
			if !ran {
				continue
			}
			for _, scanResult := range results {
				if nse.OutputIsNoise(scanResult.ScriptID, scanResult.Output) {
					continue
				}
				if nse.OutputIsError(scanResult.Output) {
					errs = append(errs, id+": "+scanResult.Output)
					continue
				}
				finding := nseFinding(host.Address, scanResult)
				finding.Risk = "Анонимная проверка протокола без эксплуатации и записи данных."
				if finding.Severity == "unknown" && strings.Contains(finding.TemplateID, "smb-vuln-ms17-010") {
					finding.Name = "MS17-010 / EternalBlue: уязвимый SMBv1"
					finding.Risk = "Проверочный SMB-запрос обнаружил признаки MS17-010; это не эксплуатация. Проверьте обновления Windows и отключите SMBv1."
				}
				findings = append(findings, finding)
			}
		}
	}
	return findings, errs
}

func enumerateAnonymousSMB(ctx context.Context, result *adscan.Result, onHost func(string)) error {
	var candidates []int
	for i := range result.Hosts {
		if containsInt(result.Hosts[i].Ports, 445) {
			candidates = append(candidates, i)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	workers := min(8, len(candidates))
	work := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range work {
				if ctx.Err() != nil {
					return
				}
				host := &result.Hosts[index]
				if onHost != nil {
					onHost(host.Address)
				}
				for _, mode := range []string{"null", "guest"} {
					probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
					entries, err := enginejs.BrowseSMBWithOptions(probeCtx, enginejs.SMBBrowseOptions{
						Host: host.Address, Port: 445, Mode: mode, EntryLimit: 32,
					}, "", "")
					cancel()
					if err != nil {
						continue
					}
					shares := make([]string, 0, len(entries))
					for _, entry := range entries {
						shares = append(shares, entry.Name)
					}
					if mode == "null" {
						host.SMBNull, host.NullShares = true, shares
					} else {
						host.SMBGuest, host.GuestShares = true, shares
					}
				}
			}
		}()
	}
	for _, index := range candidates {
		select {
		case work <- index:
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(work)
	wg.Wait()
	return ctx.Err()
}

func containsInt(values []int, value int) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func accountSample(names []string) string {
	limit := min(100, len(names))
	sample := strings.Join(names[:limit], ", ")
	if len(names) > limit {
		return fmt.Sprintf("Найдено %d; первые %d: %s", len(names), limit, sample)
	}
	return fmt.Sprintf("Найдено %d: %s", len(names), sample)
}

func adEvidenceFinding(cidr, host, key, name, evidence, risk string) domain.Finding {
	return domain.Finding{
		Description: evidence, MatcherName: "ad-" + key, Protocol: "ad", Evidence: evidence,
		TemplateID: "adscan-" + key, Name: name, Severity: "info",
		Target: cidr, MatchedAt: host, Risk: risk, Time: time.Now().UTC(),
	}
}

func adProjectName(cidr string, result adscan.Result) string {
	domainName := ""
	for _, node := range result.Hosts {
		if node.Domain != "" {
			domainName = node.Domain
			break
		}
	}
	name := "AD " + cidr
	if domainName != "" {
		name = "AD " + domainName
	}
	return fmt.Sprintf("%s — %s", name, time.Now().Format("2006-01-02 15:04"))
}

func roleContains(roles []string, role string) bool {
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func adRoleKey(role string) string {
	switch role {
	case "Контроллер домена":
		return "domain-controller"
	case "Global Catalog":
		return "global-catalog"
	case "DNS":
		return "dns"
	case "AD CS":
		return "certificate-services"
	case "LDAP":
		return "ldap"
	case "AD Web Services":
		return "ad-web-services"
	default:
		return "windows-host"
	}
}

func adPortNames(port int) (name, description string) {
	switch port {
	case 53:
		return "dns", "DNS"
	case 80:
		return "http", "HTTP"
	case 88:
		return "kerberos", "Kerberos"
	case 135:
		return "msrpc", "MS RPC"
	case 139:
		return "netbios-ssn", "NetBIOS Session Service"
	case 389:
		return "ldap", "LDAP"
	case 443:
		return "https", "HTTPS"
	case 445:
		return "smb", "SMB"
	case 464:
		return "kerberos-password", "Kerberos password change"
	case 636:
		return "ldaps", "LDAPS"
	case 3268:
		return "ldap-gc", "LDAP Global Catalog"
	case 3269:
		return "ldaps-gc", "LDAPS Global Catalog"
	case 3389:
		return "ms-wbt-server", "Remote Desktop Protocol"
	case 9389:
		return "adws", "Active Directory Web Services"
	default:
		return "unknown", fmt.Sprintf("TCP/%d", port)
	}
}

func (m model) viewADScan(w int) string {
	var body strings.Builder
	body.WriteString(headingStyle.Render("AD-аудит сети") + "\n")
	destination := "новый проект"
	if !m.adScanNewProject && m.current.ID != 0 {
		destination = fmt.Sprintf("текущий проект %q (#%d)", m.current.Name, m.current.ID)
	}
	body.WriteString("Сохранение: " + destination + " · p переключить\n")
	body.WriteString("Инвентаризация DC, Global Catalog, DNS, AD CS и Windows-служб. Без учётных данных и изменений.\n\n")
	if len(m.adNetworks) == 0 {
		body.WriteString("Активные частные IPv4-интерфейсы не найдены. Можно указать CIDR вручную.\n")
		body.WriteString(renderListRow("Ввести подсеть вручную…", m.adNetworkIndex == 0 && !m.adScanRunning, w))
	} else {
		body.WriteString("Локальные подсети (сканируется только выбранная):\n")
		for i, network := range m.adNetworks {
			line := fmt.Sprintf("%-14s  %s", network.Interface, network.CIDR)
			if i == m.adNetworkIndex {
				line += "  ·  ~" + adscan.EstimateDuration(network.CIDR).Round(time.Second).String()
			}
			body.WriteString(renderListRow(line, i == m.adNetworkIndex && !m.adScanRunning, w))
		}
		body.WriteString(renderListRow("Ввести подсеть вручную…", m.adNetworkIndex == len(m.adNetworks) && !m.adScanRunning, w))
	}

	if m.adScanRunning {
		body.WriteString("\n" + headingStyle.Render("Сканирование") + "\n")
		if m.adScanTotal > 0 {
			percent := min(int64(100), int64(m.adScanDone)*100/int64(m.adScanTotal))
			body.WriteString(fmt.Sprintf("TCP-проверки AD-портов: %d / %d (%d%%)\n", m.adScanDone, m.adScanTotal, percent))
			if job := m.jobByID(m.adScanJobID); job != nil && job.stage != "" {
				body.WriteString(job.stage + "\n")
			}
		} else {
			stage := "Подготовка диапазона…"
			if job := m.jobByID(m.adScanJobID); job != nil && job.stage != "" {
				stage = job.stage
			}
			body.WriteString(stage + "\n")
		}
		body.WriteString("Проверяются AD и Windows-порты, затем безопасные SMB/RDP-проверки и MS17-010; скорость — до 250 TCP-проверок/с. Лимита по числу адресов нет.\n")
		if len(m.adNetworks) > 0 && m.adNetworkIndex < len(m.adNetworks) {
			body.WriteString("Оценка для всей подсети: ~" + adscan.EstimateDuration(m.adNetworks[m.adNetworkIndex].CIDR).Round(time.Second).String() + "; фактическое время зависит от сети.\n")
		}
		body.WriteString("x или Esc — остановить.\n")
	}
	if m.adScanError != "" {
		body.WriteString("\n" + messageStyle.Render("Ошибка: "+m.adScanError) + "\n")
	}
	if m.adScanResult != nil {
		body.WriteString("\n" + headingStyle.Render("Результаты "+m.adScanResult.CIDR) + "\n")
		if len(m.adScanResult.Hosts) == 0 {
			body.WriteString("Открытые AD-порты не найдены.\n")
		} else {
			lo, hi := windowRange(m.serviceIndex, len(m.adScanResult.Hosts), max(1, m.panelRows()-12))
			body.WriteString(moreLine(lo, true))
			for i := lo; i < hi; i++ {
				controller := m.adScanResult.Hosts[i]
				title := controller.Address
				if controller.HostName != "" {
					title += "  " + controller.HostName
				}
				body.WriteString(headingStyle.Render(ansi.Truncate(title, max(12, w-8), "…")) + "\n")
				ports := make([]string, len(controller.Ports))
				for p, port := range controller.Ports {
					ports[p] = fmt.Sprint(port)
				}
				body.WriteString("  TCP: " + strings.Join(ports, ", ") + "\n")
				if controller.Domain != "" {
					body.WriteString("  Домен: " + controller.Domain + "\n")
				}
				if controller.LDAPMessage != "" {
					body.WriteString("  " + controller.LDAPMessage + "\n")
				}
			}
			body.WriteString(moreLine(len(m.adScanResult.Hosts)-hi, false))
		}
	}
	if m.message != "" {
		body.WriteString("\n" + messageStyle.Render(m.message) + "\n")
	}
	return m.renderPanel(w, body.String())
}
