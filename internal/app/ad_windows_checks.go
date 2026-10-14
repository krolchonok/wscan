package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"wscan/internal/adscan"
	"wscan/internal/domain"
	"wscan/internal/engine"
	enginejs "wscan/internal/engine/js"
	"wscan/internal/nse"
)

type adWindowsCheck struct {
	id, name, evidence string
	port               int
	active             bool
}

const adSMBGhostTemplate = "network/cves/2020/CVE-2020-0796.yaml"

// The plan uses discovered endpoints, not guesses about an operating system.
// Active checks keep the same project opt-in as their standalone equivalents.
func adWindowsPlan(host adscan.Host) []adWindowsCheck {
	var checks []adWindowsCheck
	if containsInt(host.Ports, 445) {
		checks = append(checks,
			adWindowsCheck{"smb-vuln-ms17-010", "MS17-010 / EternalBlue", "SMB PeekNamedPipe вернул STATUS_INSUFF_SERVER_RESOURCES (0xC0000205).", 445, false},
		)
	}
	if containsInt(host.Ports, 3389) {
		checks = append(checks,
			adWindowsCheck{"ms12-020", "MS12-020 / CVE-2012-0152", "RDP разрешил присоединение к каналу другого MCS-пользователя. Это проверка CVE-2012-0152; CVE-2012-0002 закрывается тем же обновлением, отдельно RCE не проверялось.", 3389, false},
			adWindowsCheck{"bluekeep", "BlueKeep / CVE-2019-0708", "После активации RDP и проверочных MS_T120 PDU получен MCS Disconnect Provider Ultimatum (0300000902f0802180).", 3389, false},
		)
	}
	if host.DCConfirmed && containsInt(host.Ports, 135) {
		checks = append(checks, adWindowsCheck{"zerologon", "Zerologon / CVE-2020-1472", "Netlogon NetrServerAuthenticate3 принял нулевой credential; пароль машинной учётки не изменялся.", 135, false})
	}
	// Checks with possible side effects run after all regular probes. MS08-067
	// is last because a service crash/reboot would prevent further enumeration.
	if containsInt(host.Ports, 445) {
		checks = append(checks,
			adWindowsCheck{"ms10-061", "MS10-061 / CVE-2010-2729", "NSE spoolss-проверка обнаружила уязвимый ответ RpcWritePrinter при проверочном задании печати.", 445, true},
			adWindowsCheck{"smbghost", "SMBGhost / CVE-2020-0796", "Ответ совпал с проверкой CVE-2020-0796 из библиотеки.", 445, true},
			adWindowsCheck{"ms08-067", "MS08-067 / CVE-2008-4250", "srvsvc NetprPathCompare принял проверочный некорректный путь.", 445, true},
		)
	}
	return checks
}

func (m Worker) runADWindowsChecks(ctx context.Context, hosts []adscan.Host, emit Reporter, facts ...[]domain.Finding) engine.Result {
	// One check at a time per host; bound host concurrency and retain inventory
	// order when collecting results so the UI does not depend on timing.
	results := make([]engine.Result, len(hosts))
	var capabilities map[string]adWindowsCapability
	if len(facts) > 0 {
		capabilities = adWindowsCapabilities(facts[0])
	}
	var rate <-chan time.Time
	if m.current.RPS > 0 {
		limiter := time.NewTicker(max(time.Nanosecond, time.Second/time.Duration(m.current.RPS)))
		defer limiter.Stop()
		rate = limiter.C
	}
	probe := func(ctx context.Context, host adscan.Host, check adWindowsCheck) (bool, error) {
		if rate != nil {
			select {
			case <-rate:
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}
		return m.probeADWindows(ctx, host, check)
	}
	workers := 4
	if m.current.Concurrency > 0 {
		workers = min(workers, m.current.Concurrency)
	}
	work := make(chan int)
	var wg sync.WaitGroup
	for n := 0; n < min(workers, len(hosts)); n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				results[i] = runADWindowsPlan(ctx, hosts[i:i+1], m.current.AllowExploit, emit, probe, capabilities)
			}
		}()
	}
	for i := range hosts {
		if ctx.Err() != nil {
			break
		}
		select {
		case work <- i:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()
	var out engine.Result
	for _, r := range results {
		out.Findings = append(out.Findings, r.Findings...)
		out.Errors = append(out.Errors, r.Errors...)
		out.Skipped = append(out.Skipped, r.Skipped...)
		out.Coverage = append(out.Coverage, r.Coverage...)
	}
	return out
}

type adWindowsProbe func(context.Context, adscan.Host, adWindowsCheck) (bool, error)

func runADWindowsPlan(ctx context.Context, hosts []adscan.Host, allowActive bool, emit Reporter, probe adWindowsProbe, capabilities ...map[string]adWindowsCapability) engine.Result {
	var result engine.Result
	for _, host := range hosts {
		if ctx.Err() != nil {
			return result
		}
		if containsInt(host.Ports, 445) {
			result.Skipped = append(result.Skipped, host.Address+":445 · MS06-025, MS07-029, MS10-054: проверки определяют уязвимость через сбой службы; DoS-проверки отключены")
		}
		for _, check := range adWindowsPlan(host) {
			if ctx.Err() != nil {
				return result
			}
			label := net.JoinHostPort(host.Address, strconv.Itoa(check.port)) + " · " + check.name
			cover := func(state, evidence string) {
				result.Coverage = append(result.Coverage, domain.CheckCoverage{Host: host.Address, Port: check.port, CheckID: check.id, State: state, Evidence: evidence})
			}
			if len(capabilities) > 0 {
				if reason := adWindowsCapabilitySkip(check, capabilities[0][host.Address]); reason != "" {
					cover("skipped", reason)
					result.Skipped = append(result.Skipped, label+": "+reason)
					continue
				}
			}
			if check.active && !allowActive {
				reason := "нужны активные проверки в настройках проекта"
				if check.id == "ms08-067" {
					reason += "; запрос может обрушить службу"
				}
				if check.id == "smbghost" {
					reason += "; проверка отправляет некорректный сжатый SMB-пакет"
				}
				if check.id == "ms10-061" {
					reason += "; проверка создаёт задание печати и записывает тестовые данные"
				}
				result.Skipped = append(result.Skipped, label+": "+reason)
				cover("disabled", reason)
				continue
			}
			if emit != nil {
				emit("Проверка: " + label)
			}
			vulnerable, err := probe(ctx, host, check)
			if err != nil {
				if errors.Is(err, enginejs.ErrRDPNLARequired) {
					result.Skipped = append(result.Skipped, label+": требуется NLA; без учётки статус обновления не проверен")
				} else {
					result.Errors = append(result.Errors, label+": "+err.Error())
				}
			}
			// A detected vulnerability survives an error during session cleanup.
			if vulnerable {
				result.Findings = append(result.Findings, adWindowsFinding(host, check))
				cover("confirmed", check.evidence)
			} else if err != nil {
				state := "error"
				if errors.Is(err, enginejs.ErrRDPNLARequired) {
					state = "incomplete"
				}
				cover(state, err.Error())
			} else {
				cover("negative", "Выполненный проверочный запрос не подтвердил уязвимость; это не полный аудит обновлений")
			}
		}
	}
	return result
}

type adWindowsCapability struct {
	smbKnown, smb1     bool
	rdpMajor, rdpMinor int
	rdpVersion         string
}

var adRDPNtlmVersion = regexp.MustCompile(`(?m)^\s*Product_Version:\s*(\d+)\.(\d+)(?:\.\d+)?\s*$`)
var adSMBModernDialect = regexp.MustCompile(`(?m)^\s*(?:2\.0\.2|2\.1|3\.0|3\.0\.2|3\.1\.1)\s*$`)

func adWindowsCapabilities(findings []domain.Finding) map[string]adWindowsCapability {
	out := make(map[string]adWindowsCapability)
	for _, f := range findings {
		host, port, err := net.SplitHostPort(f.Target)
		if err != nil {
			continue
		}
		cap := out[host]
		if f.TemplateID == "nmap/smb-protocols" && port == "445" {
			v1 := strings.Contains(strings.ToLower(f.Evidence), "nt lm 0.12")
			if v1 || strings.Contains(f.Evidence, "dialects:") && adSMBModernDialect.MatchString(f.Evidence) {
				cap.smbKnown = true
				cap.smb1 = cap.smb1 || v1
			}
		}
		if f.TemplateID == "nmap/rdp-ntlm-info" && port == "3389" {
			if match := adRDPNtlmVersion.FindStringSubmatch(f.Evidence); len(match) > 0 {
				cap.rdpMajor, _ = strconv.Atoi(match[1])
				cap.rdpMinor, _ = strconv.Atoi(match[2])
				cap.rdpVersion = strings.TrimSpace(strings.SplitN(strings.TrimSpace(match[0]), ":", 2)[1])
			}
		}
		out[host] = cap
	}
	return out
}

func adWindowsCapabilitySkip(check adWindowsCheck, cap adWindowsCapability) string {
	if check.id == "smb-vuln-ms17-010" && cap.smbKnown && !cap.smb1 {
		return "SMBv1 не поддерживается: подтверждено smb-protocols"
	}
	if (check.id == "ms12-020" || check.id == "bluekeep") && (cap.rdpMajor > 6 || cap.rdpMajor == 6 && cap.rdpMinor >= 2) {
		return "версия Windows " + cap.rdpVersion + " вне затронутых версий: rdp-ntlm-info"
	}
	return ""
}

func adWindowsFinding(host adscan.Host, check adWindowsCheck) domain.Finding {
	endpoint := net.JoinHostPort(host.Address, strconv.Itoa(check.port))
	risk := "Проверка уязвимости без эксплуатации и записи данных."
	if check.active {
		risk = "Активная проверка разрешена настройками проекта; возможен сбой службы."
	}
	return domain.Finding{
		TemplateID: "adscan-" + check.id, MatcherName: check.id,
		Name: check.name, Severity: "critical", Protocol: "tcp",
		Target: endpoint, MatchedAt: "tcp://" + endpoint,
		Description: check.evidence, Evidence: check.evidence, Risk: risk, Time: time.Now().UTC(),
	}
}

func (m Worker) probeADWindows(ctx context.Context, host adscan.Host, check adWindowsCheck) (bool, error) {
	timeout := 10 * time.Second
	if m.current.TimeoutSeconds > 0 {
		timeout = time.Duration(m.current.TimeoutSeconds) * time.Second
	}
	switch check.id {
	case "smb-vuln-ms17-010":
		return enginejs.CheckMS17010(ctx, host.Address, check.port, timeout)
	case "ms08-067":
		return enginejs.CheckMS08067(ctx, host.Address, check.port, timeout)
	case "ms10-061":
		return m.probeADMS10061(ctx, host, timeout)
	case "ms12-020":
		return enginejs.CheckMS12020(ctx, host.Address, check.port, timeout)
	case "bluekeep":
		return enginejs.CheckBlueKeep(ctx, host.Address, check.port, timeout)
	case "zerologon":
		// RootDSE's dnsHostName alone is not always the NetBIOS name. Ask the
		// target directly, then fall back only to a valid short DNS host name.
		name, err := enginejs.ResolveNetBIOSName(ctx, host.Address, 137, min(timeout, 3*time.Second))
		if err != nil {
			name = adDCComputerName(host.HostName)
		}
		if name == "" {
			return false, fmt.Errorf("не удалось определить NetBIOS-имя DC; проверка не выполнена")
		}
		return enginejs.CheckZerologon(ctx, host.Address, name, timeout)
	case "smbghost":
		return m.probeADSMBGhost(ctx, host)
	default:
		return false, fmt.Errorf("unknown AD check %s", check.id)
	}
}

func (m Worker) probeADMS10061(ctx context.Context, host adscan.Host, timeout time.Duration) (bool, error) {
	if !m.current.AllowExploit {
		return false, fmt.Errorf("активные проверки отключены")
	}
	id := "nmap/scripts/smb-vuln-ms10-061.nse"
	if _, err := m.cat.Load(ctx, id); err != nil {
		return false, err
	}
	runner := nse.New(m.cat.LibraryDir(), nse.Config{Timeout: min(timeout, 3*time.Second), ScriptTimeout: timeout, RPS: 4, SelectedServicesOnly: true})
	results, ran, err := runner.Run(ctx, filepath.Join(m.cat.LibraryDir(), filepath.FromSlash(id)), nse.HostInfo{IP: host.Address}, []nse.PortInfo{{Number: 445, Protocol: "tcp", State: "open", Service: "smb"}})
	if err != nil {
		return false, err
	}
	if !ran || len(results) == 0 {
		return false, fmt.Errorf("нет результата; требуется доступная общая папка принтера или учётка")
	}
	for _, result := range results {
		if nse.OutputIsError(result.Output) {
			return false, fmt.Errorf("%s", result.Output)
		}
		if nse.OutputSeverity(result.Output) == "unknown" {
			return true, nil
		}
		if strings.Contains(strings.ToUpper(result.Output), "NOT VULNERABLE") {
			return false, nil
		}
	}
	return false, fmt.Errorf("проверка не установила статус MS10-061")
}

func adDCComputerName(hostname string) string {
	name := strings.Split(strings.TrimSuffix(hostname, "."), ".")[0]
	if len(name) == 0 || len(name) > 15 || net.ParseIP(hostname) != nil {
		return ""
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return ""
		}
	}
	return strings.ToUpper(name)
}

func (m Worker) probeADSMBGhost(ctx context.Context, host adscan.Host) (bool, error) {
	// Guard before even loading the template: its legacy "safe" tag does not
	// describe the risk of the malformed compressed packet it sends.
	if !m.current.AllowExploit {
		return false, fmt.Errorf("активные проверки отключены")
	}
	templates, errs := m.compileTemplates(ctx, []string{adSMBGhostTemplate})
	if len(errs) > 0 {
		return false, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	if len(templates) != 1 {
		return false, fmt.Errorf("шаблон SMBGhost отсутствует")
	}
	templates[0].IsExploit, templates[0].Risk = true, "intrusive"
	p := m.current
	p.Targets, p.ScanTargets, p.Services = []string{host.Address}, nil, nil
	p.UseDiscoveredTargets, p.DiscoveryEnabled, p.Retries = false, false, 0
	p.Concurrency = 1
	e := engine.New(adTransientSaver{}, engine.Config{LibraryDir: m.cat.LibraryDir()})
	r, err := e.Scan(ctx, p, templates)
	if err != nil {
		return len(r.Findings) > 0, err
	}
	if len(r.Errors)+len(r.Skipped) > 0 {
		return len(r.Findings) > 0, fmt.Errorf("%s", strings.Join(append(r.Errors, r.Skipped...), "; "))
	}
	return len(r.Findings) > 0, nil
}

// Template checks feed the enclosing AD run. They must not create independent
// database runs or duplicate findings/services in the project.
type adTransientSaver struct{}

func (adTransientSaver) StartRun(context.Context, int64) (int64, error)           { return 0, nil }
func (adTransientSaver) SaveFinding(context.Context, int64, domain.Finding) error { return nil }
func (adTransientSaver) SaveService(context.Context, int64, domain.Service) error { return nil }
func (adTransientSaver) FinishRun(context.Context, int64, string) error           { return nil }
func (adTransientSaver) RecordAttempt(context.Context, int64, string, string, string, bool) error {
	return nil
}
func (adTransientSaver) RecentFailureCount(context.Context, int64, string, time.Time) (int, error) {
	return 0, nil
}
