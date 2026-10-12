package app

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"wscan/internal/adscan"
	"wscan/internal/domain"
	"wscan/internal/engine"
	enginejs "wscan/internal/engine/js"
	"wscan/internal/nse"
)

func (m Worker) adResultProject(ctx context.Context, cidr string, details adscan.Result) (int64, string, error) {
	targets := strings.Fields(cidr)
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

func (m Worker) runADScan(ctx context.Context, cidr string, emit Reporter) (engine.Result, *adscan.Result, int64, string, error) {
	details, err := adscan.Discover(ctx, cidr, m.adScanDNS, func(stage string, done, total int) {
		if total > 0 {
			emit(stage+": "+cidr, done, total)
		} else {
			emit(stage)
		}
	})
	if err != nil {
		return engine.Result{}, &details, 0, "", err
	}
	if err := enumerateAnonymousSMB(ctx, &details, func(host string) {
		emit("Проверяю анонимный SMB: " + host)
	}); err != nil {
		return engine.Result{}, &details, 0, "", err
	}
	dnsErrors := details.Diagnostics
	for _, diagnostic := range dnsErrors {
		emit(diagnostic)
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
			if node.DCConfirmed && (port == 389 || port == 636 || port == 3268 || port == 3269 || port == 88 || port == 464 || port == 9389) {
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
			description := role + " предполагается по доступным портам или ответам сервиса."
			if role == "Контроллер домена" {
				description = "Контроллер домена подтверждён LDAP RootDSE (AD DS; AD LDS исключён)."
			}
			if role == "Предполагаемый контроллер домена" {
				description = "Предполагаемый DC: сочетание Kerberos/LDAP или DNS SRV; LDAP-подтверждения AD DS нет."
			}
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
				Target: cidr, MatchedAt: node.Address, Risk: "Сетевая разведка; предположения отделены от LDAP-подтверждения роли DC.", Time: time.Now().UTC(),
			}
			if err := m.store.SaveFinding(ctx, runID, finding); err != nil {
				status = "failed"
				return result, &details, projectID, projectName, err
			}
			result.Findings = append(result.Findings, finding)
		}
		if node.LDAPMessage != "" {
			description := "Анонимный LDAP RootDSE"
			if node.LDAPMessage != "" {
				description += "; " + node.LDAPMessage
			}
			if node.Domain != "" {
				description += "; домен: " + node.Domain
			}
			if node.HostName != "" {
				description += "; имя узла: " + node.HostName
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
		if len(node.Identity) > 0 {
			var facts []string
			for _, fact := range node.Identity {
				facts = append(facts, fact.Kind+": "+fact.Value+" · источник: "+fact.Source)
			}
			finding := adEvidenceFinding(cidr, node.Address, "identity", "Идентификация узла и источники", strings.Join(facts, "\n"), "DNS-объявление сервиса и имя узла не подтверждают роль DC; противоречащие сведения сохраняются с источниками.")
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
		byServer[record.Server] = append(byServer[record.Server], fmt.Sprintf("%s → %s:%d (priority %d, weight %d; DNS port %d)", record.Query, record.Target, record.Port, record.Priority, record.Weight, record.ServerPort))
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
	var dc, gc, dns, adcs, smbAnonymous, probableDC int
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
		if roleContains(host.Roles, "Предполагаемый контроллер домена") {
			probableDC++
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
	evidence += fmt.Sprintf("\nПредполагаемые DC: %d (не входят в число подтверждённых).", probableDC)
	for _, record := range result.DNSRecords {
		domains = append(domains, record.Domain)
	}
	if len(result.Diagnostics) > 0 {
		evidence += "\nОграничения покрытия:\n" + strings.Join(result.Diagnostics, "\n")
	}
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

func (m Worker) runADNSEChecks(ctx context.Context, hosts []adscan.Host, emit Reporter) ([]domain.Finding, []string) {
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
	case "Предполагаемый контроллер домена":
		return "domain-controller-candidate"
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

func ADDNSFindings(cidr string, records []adscan.SRVRecord) []domain.Finding {
	return adDNSFindings(cidr, records)
}

func ADReconSummary(cidr string, result adscan.Result, findings []domain.Finding) domain.Finding {
	return adReconSummary(cidr, result, findings)
}

func ADEvidenceFinding(cidr, host, key, name, evidence, risk string) domain.Finding {
	return adEvidenceFinding(cidr, host, key, name, evidence, risk)
}

func ADProjectName(cidr string, result adscan.Result) string { return adProjectName(cidr, result) }

func ADRoleKey(role string) string { return adRoleKey(role) }

func ADPortNames(port int) (name, description string) { return adPortNames(port) }

func AccountSample(names []string) string { return accountSample(names) }

func RoleContains(roles []string, role string) bool { return roleContains(roles, role) }

func ContainsInt(values []int, value int) bool { return containsInt(values, value) }

func (m Worker) AdResultProject(ctx context.Context, cidr string, details adscan.Result) (int64, string, error) {
	return m.adResultProject(ctx, cidr, details)
}

func (m Worker) RunADScan(ctx context.Context, cidr string, emit Reporter) (engine.Result, *adscan.Result, int64, string, error) {
	return m.runADScan(ctx, cidr, emit)
}

func (m Worker) RunADNSEChecks(ctx context.Context, hosts []adscan.Host, emit Reporter) ([]domain.Finding, []string) {
	return m.runADNSEChecks(ctx, hosts, emit)
}
