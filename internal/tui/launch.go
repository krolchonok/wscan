package tui

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"wscan/internal/catalog"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
	tpl "wscan/internal/template"
	"wscan/internal/workflow"
)

// launchSpec describes one action chosen from the action menu, resolved into
// concrete targets/templates before starting a background job.
type launchSpec struct {
	dnsServer   string
	kind        string // jobDiscover, jobChecks, jobFull, jobPort
	label       string
	hosts       []string
	templateIDs []string
	service     *domain.Service // set for jobPort
	services    []domain.Service
	port        int
	protocol    string
	parameters  *domain.Project

	// discovery options (jobDiscover)
	discPorts     []int
	discUDPPorts  []int
	discAllPorts  bool
	discSkipTCP   bool
	discNoVersion bool
	discOnlyKnown bool
	discNoPing    bool
}

type reportingChecks struct {
	engine *engine.Engine
	emit   progressReporter
}

func (r reportingChecks) Scan(ctx context.Context, p domain.Project, templates []domain.Template) (engine.Result, error) {
	r.emit("Nuclei")
	return r.engine.ScanProgress(ctx, p, templates, func(done, total int) { r.emit("Nuclei", done, total) })
}

// startLaunch turns a spec into a running background job.
func (m *model) startLaunch(spec launchSpec) {
	worker := *m
	if spec.parameters != nil {
		worker.current = *spec.parameters
	}
	fn := worker.buildRunFunc(spec)
	m.launch(spec.kind, spec.label, spec.hosts, fn)
	j := m.jobs[len(m.jobs)-1]
	j.checks = append([]string(nil), spec.templateIDs...)
	if len(spec.templateIDs) > 0 {
		j.options = append(j.options, "Воздействие: "+m.selectedImpactSummary())
	}
	j.options = append(j.options, fmt.Sprintf("HTTP: RPS %d, параллельность %d, timeout %ds, повторы %d", worker.current.RPS, worker.current.Concurrency, worker.current.TimeoutSeconds, worker.current.Retries))
	j.scope = "Хосты: " + strings.Join(spec.hosts, ", ")
	if spec.kind == jobBulkPort {
		j.scope = fmt.Sprintf("Только порт %d/%s · %d хостов", spec.port, spec.protocol, len(spec.hosts))
		j.options = append(j.options, "Только известные открытые порты; поиск других портов отключён")
	} else if spec.service != nil {
		service := *spec.service
		j.service = &service
		j.scope = fmt.Sprintf("Только порт %d/%s · %s", service.Port, service.Protocol, service.Host)
		j.options = append(j.options, "Поиск других портов отключён")
	} else if spec.kind == jobChecks {
		j.scope += " · все известные порты"
	}
	if spec.kind == jobFull {
		j.checks = append([]string(nil), m.current.TemplateIDs...)
		j.options = append(j.options, fmt.Sprintf("Discovery: %t, полный диапазон TCP: %t", m.current.DiscoveryEnabled, m.current.AllPorts))
	}
	if spec.kind == jobDiscover {
		j.options = append(j.options, "Добавлять: "+portResultPolicy(spec.discOnlyKnown))
		j.options = append(j.options, fmt.Sprintf("Поиск портов: RPS %d, параллельность %d", worker.current.DiscoveryRPS, worker.current.DiscoveryConcurrency))
		j.options = append(j.options, fmt.Sprintf("TCP: %t · UDP: %t · версии сервисов: %t", !spec.discSkipTCP, len(spec.discUDPPorts) > 0, !spec.discNoVersion))
		j.options = append(j.options, fmt.Sprintf("Host discovery: %t · -Pn: %t", !spec.discNoPing, spec.discNoPing))
		ports := "Common"
		if spec.discAllPorts {
			ports = "1–65535"
		} else if len(spec.discPorts) > 0 {
			ports = fmt.Sprint(spec.discPorts)
		}
		j.options = append(j.options, "Порты TCP: "+ports, fmt.Sprintf("Порты UDP: %v", spec.discUDPPorts))
	}
	if spec.kind == jobPTR {
		j.options = append(j.options, "DNS-сервер: "+spec.dnsServer, fmt.Sprintf("PTR: RPS %d, параллельность %d, timeout %ds", worker.current.DiscoveryRPS, worker.current.DiscoveryConcurrency, worker.current.TimeoutSeconds))
	}
	m.initJobLog(j)
}

func (m model) buildRunFunc(spec launchSpec) runFunc {
	switch spec.kind {
	case jobPTR:
		return m.runPTR(spec)
	case jobAlive:
		return m.runAliveHosts(spec)
	case jobDiscover:
		return m.runDiscover(spec)
	case jobChecks:
		return m.runChecks(spec.hosts, spec.templateIDs)
	case jobFull:
		return m.runFull(spec.hosts)
	case jobBulkPort:
		return m.runServiceChecks(spec.services, spec.templateIDs)
	case jobPort:
		return m.runPortChecks(*spec.service, spec.templateIDs)
	}
	return func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		return engine.Result{}, fmt.Errorf("unknown action")
	}
}

func (m model) runAliveHosts(spec launchSpec) runFunc {
	return func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		hasNetwork := false
		for _, target := range spec.hosts {
			hasNetwork = hasNetwork || discovery.IsNetworkTarget(target)
		}
		if !hasNetwork {
			return engine.Result{}, fmt.Errorf("добавь цель-подсеть в формате CIDR, например 10.0.0.0/24")
		}
		emit("ARP / ICMP / TCP host discovery…")
		timeout := 700 * time.Millisecond
		hosts, err := discovery.LiveHosts(ctx, spec.hosts, m.current.DiscoveryConcurrency, m.current.DiscoveryRPS, timeout, func(done, total int) {
			emit("Проверка доступности", done, total)
		})
		if err != nil {
			return engine.Result{}, err
		}
		return engine.Result{LiveHosts: hosts}, nil
	}
}

// splitFamilies separates selected template IDs into Nuclei templates and Nmap
// NSE scripts so each goes to its own engine.
func splitFamilies(ids []string) (nuclei, nse []string) {
	for _, id := range ids {
		if strings.HasPrefix(id, "nmap/scripts/") {
			nse = append(nse, id)
		} else {
			nuclei = append(nuclei, id)
		}
	}
	return
}

var discSetLabels = []string{"Common (встроенный список)", "Top 100", "Top 1000", "Все порты 1–65535", "Свой список"}

// buildDiscoverSpec turns the discovery-options screen state into a launch spec,
// or returns a user-facing error string.
func (m model) buildDiscoverSpec() (launchSpec, string) {
	lib := m.cat.LibraryDir()
	spec := launchSpec{kind: jobDiscover, hosts: m.discHosts, discNoVersion: !m.discVersion, discNoPing: m.discNoPing}
	parameters := m.discProject
	spec.parameters = &parameters
	spec.discOnlyKnown = m.discOnlyKnown
	if !m.discTCP && !m.discUDP {
		return spec, "Выбери TCP и/или UDP"
	}
	if m.discTCP {
		switch m.discSetIndex {
		case 0: // common: leave discPorts nil so the engine uses its built-in list
		case 1:
			spec.discPorts = discovery.TopPorts(lib, "tcp", 100)
		case 2:
			spec.discPorts = discovery.TopPorts(lib, "tcp", 1000)
		case 3:
			spec.discAllPorts = true
		case 4:
			spec.discPorts = discovery.ParsePortList(m.discCustom)
			if len(spec.discPorts) == 0 {
				return spec, "Пустой или некорректный список портов"
			}
		}
	} else {
		spec.discSkipTCP = true
	}
	if m.discUDP {
		switch m.discSetIndex {
		case 0:
			spec.discUDPPorts = discovery.TopPorts(lib, "udp", 50)
		case 1:
			spec.discUDPPorts = discovery.TopPorts(lib, "udp", 100)
		case 2, 3:
			spec.discUDPPorts = discovery.TopPorts(lib, "udp", 1000)
		case 4:
			spec.discUDPPorts = discovery.ParsePortList(m.discCustom)
			if len(spec.discUDPPorts) == 0 {
				return spec, "Пустой или некорректный список портов"
			}
		}
	}
	proto := "TCP"
	if spec.discSkipTCP {
		proto = "UDP"
	} else if m.discUDP {
		proto = "TCP+UDP"
	}
	spec.label = fmt.Sprintf("Discover %s: %s", proto, strings.Join(m.discHosts, ", "))
	return spec, ""
}

// runDiscover runs the built-in TCP/UDP connect scanner against the given
// hosts with the options chosen on the discovery-options screen.
func (m model) runDiscover(spec launchSpec) runFunc {
	return func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		proto := "TCP"
		if spec.discSkipTCP {
			proto = "UDP"
		} else if len(spec.discUDPPorts) > 0 {
			proto = "TCP+UDP"
		}
		emit(fmt.Sprintf("%s discovery на %d целях…", proto, len(spec.hosts)))
		p := m.current
		var expanded []string
		var networks []string
		for _, target := range spec.hosts {
			if discovery.IsNetworkTarget(target) && !spec.discNoPing {
				networks = append(networks, target)
			} else if discovery.IsNetworkTarget(target) {
				addresses, err := discovery.ExpandCIDR(target)
				if err != nil {
					return engine.Result{}, err
				}
				expanded = append(expanded, addresses...)
			} else {
				expanded = append(expanded, target)
			}
		}
		var liveHosts []string
		if len(networks) > 0 {
			emit("ARP / ICMP / TCP host discovery…")
			found, err := discovery.LiveHosts(ctx, networks, p.DiscoveryConcurrency, p.DiscoveryRPS, 700*time.Millisecond, func(done, total int) {
				emit("Проверка доступности", done, total)
			})
			if err != nil {
				return engine.Result{}, err
			}
			liveHosts = uniqueStrings(found)
			expanded = append(expanded, liveHosts...)
			if len(liveHosts) == 0 {
				emit("Хосты не ответили на ICMP и TCP-пробы; попробуй -Pn")
				return engine.Result{LiveHosts: liveHosts}, nil
			}
		}
		p.Targets = uniqueStrings(expanded)
		p.TemplateIDs = nil
		p.DiscoveryEnabled = true
		p.AllPorts = spec.discAllPorts
		discoverer := discovery.Scanner{Config: discovery.Config{
			LibraryDir:        m.cat.LibraryDir(),
			OnlyKnownServices: spec.discOnlyKnown,
			RPS:               p.DiscoveryRPS,
			Concurrency:       p.DiscoveryConcurrency,
			AllPorts:          spec.discAllPorts,
			Ports:             spec.discPorts,
			UDPPorts:          spec.discUDPPorts,
			NoVersion:         spec.discNoVersion,
			Progress:          func(target string, done, total int) { emit("Порты: "+target, done, total) },
			SkipTCP:           spec.discSkipTCP,
		}}
		runner := workflow.Runner{Discovery: discoverer, HTTP: m.scanner}
		result, err := runner.Run(ctx, p, nil)
		result.LiveHosts = liveHosts
		return result, err
	}
}

// runChecks runs the selected checks (Nuclei templates and/or Nmap NSE scripts,
// mixed) against already-known services on the given hosts. One job, one run,
// live progress — the user never thinks about which engine runs what.
func (m model) runChecks(hosts []string, templateIDs []string) runFunc {
	return func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		services := m.knownServices(hosts)
		if len(services) == 0 {
			return engine.Result{}, fmt.Errorf("нет известных портов на выбранных хостах — сначала выполни Discover ports")
		}
		nucleiIDs, nseIDs := splitFamilies(templateIDs)
		if len(nucleiIDs) == 0 && len(nseIDs) == 0 {
			return engine.Result{}, fmt.Errorf("не выбрано ни одной проверки")
		}
		webTargets := m.knownWebTargets(hosts)
		templates, loadErrs := m.compileTemplates(ctx, nucleiIDs)
		emit(fmt.Sprintf("проверки: %d Nuclei + %d NSE…", len(templates), len(nseIDs)))
		p := m.current
		p.Targets = webTargets
		p.DiscoveryEnabled = false
		p.UseDiscoveredTargets = true
		p.ScanTargets = webTargets
		p.Services = services
		res, err := m.scanner.ScanProgress(ctx, p, templates, func(d, t int) {
			emit("Nuclei", d, t)
		})
		if err != nil {
			return res, err
		}
		res.Errors = append(res.Errors, loadErrs...)
		if len(nseIDs) > 0 {
			findings, errs := m.runNmapScripts(ctx, hosts, nseIDs, emit)
			res.Errors = append(res.Errors, errs...)
			for _, f := range findings {
				if saveErr := m.store.SaveFinding(ctx, res.RunID, f); saveErr != nil {
					res.Errors = append(res.Errors, "save nse result: "+saveErr.Error())
				} else {
					res.Findings = append(res.Findings, f)
				}
			}
		}
		return res, nil
	}
}

// runPortChecks restricts the selected checks to exactly one discovered service.
func (m model) runPortChecks(service domain.Service, templateIDs []string) runFunc {
	return m.runServiceChecks([]domain.Service{service}, templateIDs)
}

func (m model) runServiceChecks(services []domain.Service, templateIDs []string) runFunc {
	return func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		if len(services) == 0 {
			return engine.Result{}, fmt.Errorf("нет подходящих сервисов")
		}
		service := services[0]
		for _, candidate := range services {
			if catalog.ServiceDirection(candidate) == "Web" {
				service = candidate
				break
			}
		}
		var skippedWeb []string
		templateIDs, skippedWeb = servicesCompatibleTemplateIDs(m.entries, services, templateIDs)
		for _, id := range skippedWeb {
			emit("Проверка: " + id + " — пропущено: проверка не подходит к выбранному сервису")
		}
		nucleiIDs, nseIDs := splitFamilies(templateIDs)
		if len(nucleiIDs) == 0 && len(nseIDs) == 0 {
			if len(skippedWeb) > 0 {
				return engine.Result{}, nil
			}
			return engine.Result{}, fmt.Errorf("не выбрано ни одной проверки")
		}
		emit(fmt.Sprintf("проверки только порта %d/%s на %d сервисах…", service.Port, service.Protocol, len(services)))
		p := m.current
		p.Targets = nil
		p.ScanTargets = nil
		for _, s := range services {
			p.Targets = append(p.Targets, s.Host)
			p.ScanTargets = append(p.ScanTargets, portURL(s))
		}
		p.Targets = uniqueStrings(p.Targets)
		p.DiscoveryEnabled = false
		p.UseDiscoveredTargets = true

		p.Services = append([]domain.Service(nil), services...)
		templates, loadErrs := m.compileTemplates(ctx, nucleiIDs)
		res, err := m.scanner.ScanProgress(ctx, p, templates, func(d, t int) {
			emit("Nuclei", d, t)
		})
		if err != nil {
			return res, err
		}
		res.Errors = append(res.Errors, loadErrs...)
		if len(nseIDs) > 0 {
			findings, errs := m.runNmapScriptsForServices(ctx, services, nseIDs, emit)
			res.Errors = append(res.Errors, errs...)
			for _, f := range findings {
				if saveErr := m.store.SaveFinding(ctx, res.RunID, f); saveErr != nil {
					res.Errors = append(res.Errors, "save nse result: "+saveErr.Error())
				} else {
					res.Findings = append(res.Findings, f)
				}
			}
		}
		return res, nil
	}
}

func portCompatibleTemplateIDs(entries []catalog.Entry, service domain.Service, ids []string) (compatible, skipped []string) {

	byID := make(map[string]catalog.Entry, len(entries)*2)
	for _, entry := range entries {
		byID[entry.Path] = entry
		if entry.TemplateID != "" {
			byID[entry.TemplateID] = entry
		}
	}
	for _, id := range ids {
		entry, ok := byID[id]
		wrongDB := false
		if ok && catalog.Direction(entry) == "Базы данных" {
			actual, expected := domain.ServiceDatabase(service), catalog.DatabaseType(entry)
			wrongDB = actual != "" && expected != "Прочие БД" && actual != expected
		}
		if wrongDB || ok && catalog.Direction(entry) == "Web" && catalog.ServiceDirection(service) != "Web" {
			skipped = append(skipped, id)
			continue
		}
		compatible = append(compatible, id)
	}
	return compatible, skipped
}

// runFull replays the project's configured default checks together with a fresh
// discovery pass.
func (m model) runFull(hosts []string) runFunc {
	return func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		emit(fmt.Sprintf("полный скан: discovery + %d проверок…", len(m.current.TemplateIDs)))
		p := m.current
		var expanded []string
		for _, target := range hosts {
			if discovery.IsNetworkTarget(target) {
				addresses, err := discovery.ExpandCIDR(target)
				if err != nil {
					return engine.Result{}, err
				}
				expanded = append(expanded, addresses...)
			} else {
				expanded = append(expanded, target)
			}
		}
		p.Targets = uniqueStrings(expanded)
		templates, nseIDs, loadErrs := m.compileTemplatesGrouped(ctx, m.current.TemplateIDs)
		discoverer := discovery.Scanner{Config: discovery.Config{LibraryDir: m.cat.LibraryDir(), RPS: p.DiscoveryRPS, Concurrency: p.DiscoveryConcurrency, AllPorts: p.AllPorts, Progress: func(target string, done, total int) { emit("Порты: "+target, done, total) }}}
		runner := workflow.Runner{Discovery: discoverer, HTTP: reportingChecks{m.scanner, emit}}
		res, err := runner.Run(ctx, p, templates)
		if err != nil {
			return res, err
		}
		if len(nseIDs) > 0 {
			findings, errs := m.runNmapScriptsForServices(ctx, res.Services, nseIDs, emit)
			res.Errors = append(res.Errors, errs...)
			for _, f := range findings {
				if saveErr := m.store.SaveFinding(ctx, res.RunID, f); saveErr != nil {
					res.Errors = append(res.Errors, "save nse result: "+saveErr.Error())
				} else {
					res.Findings = append(res.Findings, f)
				}
			}
		}
		res.Errors = append(res.Errors, loadErrs...)
		return res, nil
	}
}

func portURL(s domain.Service) string {
	scheme := "http"
	if strings.EqualFold(s.Tunnel, "tls") || strings.EqualFold(s.Tunnel, "ssl") || s.Port == 5986 || strings.Contains(strings.ToLower(s.Name), "https") || s.Port == 443 || s.Port == 8443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(s.Host, fmt.Sprint(s.Port)))
}

// compileTemplates loads and parses the given Nuclei template IDs for the
// selected engine. Complete documents are retained for Nuclei; without it,
// native parser limitations are reported in loadErrs. NSE ids are ignored here.
func (m model) compileTemplates(ctx context.Context, ids []string) (templates []domain.Template, loadErrs []string) {
	impacts := map[string]string{}
	for _, entry := range m.entries {
		impacts[entry.Path] = catalog.Impact(entry)
	}
	for _, id := range ids {
		if strings.HasPrefix(id, "nmap/scripts/") {
			continue
		}
		b, err := m.cat.Load(ctx, id)
		if err != nil {
			loadErrs = append(loadErrs, id+": "+err.Error())
			continue
		}
		t, err := tpl.ForExecution(b, id)
		if err != nil {
			loadErrs = append(loadErrs, id+": "+err.Error())
			continue
		}
		if !t.Compatible {
			reason := "несовместимый шаблон"
			if len(t.Unsupported) > 0 {
				reason = t.Unsupported[0]
			}
			loadErrs = append(loadErrs, id+": "+reason)
			continue
		}
		switch impacts[id] {
		case catalog.ImpactDiscovery:
			t.Risk = "read-only"
		case catalog.ImpactStrong:
			t.Risk = "intrusive"
		}
		templates = append(templates, t)
	}
	return
}

// compileTemplatesGrouped is compileTemplates plus NSE id separation, used by
// the full-scan action which mixes both families.
func (m model) compileTemplatesGrouped(ctx context.Context, ids []string) (templates []domain.Template, nseIDs []string, loadErrs []string) {
	var nucleiIDs []string
	for _, id := range ids {
		if strings.HasPrefix(id, "nmap/scripts/") {
			nseIDs = append(nseIDs, id)
		} else {
			nucleiIDs = append(nucleiIDs, id)
		}
	}
	templates, loadErrs = m.compileTemplates(ctx, nucleiIDs)
	return
}

func servicesCompatibleTemplateIDs(entries []catalog.Entry, services []domain.Service, ids []string) (compatible, skipped []string) {
	allowed := map[string]bool{}
	for _, service := range services {
		matching, _ := portCompatibleTemplateIDs(entries, service, ids)
		for _, id := range matching {
			allowed[id] = true
		}
	}
	for _, id := range ids {
		if allowed[id] {
			compatible = append(compatible, id)
		} else {
			skipped = append(skipped, id)
		}
	}
	return
}
