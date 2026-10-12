package app

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

func (m Worker) runAliveHosts(spec Spec) RunFunc {
	return func(ctx context.Context, emit Reporter) (engine.Result, error) {
		hasNetwork := false
		for _, target := range spec.Hosts {
			hasNetwork = hasNetwork || discovery.IsNetworkTarget(target)
		}
		if !hasNetwork {
			return engine.Result{}, fmt.Errorf("добавь цель-подсеть в формате CIDR, например 10.0.0.0/24")
		}
		emit("ARP / ICMP / TCP host discovery…")
		timeout := 700 * time.Millisecond
		hosts, err := discovery.LiveHosts(ctx, spec.Hosts, m.current.DiscoveryConcurrency, m.current.DiscoveryRPS, timeout, func(done, total int) {
			emit("Проверка доступности", done, total)
		})
		if err != nil {
			return engine.Result{}, err
		}
		return engine.Result{LiveHosts: hosts}, nil
	}
}

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

func (m Worker) runDiscover(spec Spec) RunFunc {
	return func(ctx context.Context, emit Reporter) (engine.Result, error) {
		proto := "TCP"
		if spec.DiscSkipTCP {
			proto = "UDP"
		} else if len(spec.DiscUDPPorts) > 0 {
			proto = "TCP+UDP"
		}
		emit(fmt.Sprintf("%s discovery на %d целях…", proto, len(spec.Hosts)))
		p := m.current
		var expanded []string
		var networks []string
		for _, target := range spec.Hosts {
			if discovery.IsNetworkTarget(target) && !spec.DiscNoPing {
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
		p.AllPorts = spec.DiscAllPorts
		discoverer := discovery.Scanner{Config: discovery.Config{
			LibraryDir:        m.cat.LibraryDir(),
			OnlyKnownServices: spec.DiscOnlyKnown,
			RPS:               p.DiscoveryRPS,
			Concurrency:       p.DiscoveryConcurrency,
			AllPorts:          spec.DiscAllPorts,
			Ports:             spec.DiscPorts,
			UDPPorts:          spec.DiscUDPPorts,
			NoVersion:         spec.DiscNoVersion,
			Progress:          func(target string, done, total int) { emit("Порты: "+target, done, total) },
			SkipTCP:           spec.DiscSkipTCP,
		}}
		runner := workflow.Runner{Discovery: discoverer, HTTP: m.scanner}
		result, err := runner.Run(ctx, p, nil)
		result.LiveHosts = liveHosts
		return result, err
	}
}

func (m Worker) runChecks(hosts []string, templateIDs []string) RunFunc {
	return func(ctx context.Context, emit Reporter) (engine.Result, error) {
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

func (m Worker) runPortChecks(service domain.Service, templateIDs []string) RunFunc {
	return m.runServiceChecks([]domain.Service{service}, templateIDs)
}

func (m Worker) runServiceChecks(services []domain.Service, templateIDs []string) RunFunc {
	return func(ctx context.Context, emit Reporter) (engine.Result, error) {
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

func (m Worker) runFull(hosts []string) RunFunc {
	return m.runFullSpec(Spec{Hosts: hosts})
}

func (m Worker) runFullSpec(spec Spec) RunFunc {
	hosts := spec.Hosts
	return func(ctx context.Context, emit Reporter) (engine.Result, error) {
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
		discoverer := discovery.Scanner{Config: discovery.Config{LibraryDir: m.cat.LibraryDir(), RPS: p.DiscoveryRPS, Concurrency: p.DiscoveryConcurrency, AllPorts: p.AllPorts && len(spec.DiscPorts) == 0, Ports: spec.DiscPorts, UDPPorts: spec.DiscUDPPorts, NoVersion: spec.DiscNoVersion, SkipTCP: spec.DiscSkipTCP, Progress: func(target string, done, total int) { emit("Порты: "+target, done, total) }}}
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

func (m Worker) compileTemplates(ctx context.Context, ids []string) (templates []domain.Template, loadErrs []string) {
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

func (m Worker) compileTemplatesGrouped(ctx context.Context, ids []string) (templates []domain.Template, nseIDs []string, loadErrs []string) {
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

func PortCompatibleTemplateIDs(entries []catalog.Entry, service domain.Service, ids []string) (compatible, skipped []string) {
	return portCompatibleTemplateIDs(entries, service, ids)
}

func ServicesCompatibleTemplateIDs(entries []catalog.Entry, services []domain.Service, ids []string) (compatible, skipped []string) {
	return servicesCompatibleTemplateIDs(entries, services, ids)
}

func PortURL(s domain.Service) string { return portURL(s) }

func SplitFamilies(ids []string) (nuclei, nse []string) { return splitFamilies(ids) }

func (m Worker) RunAliveHosts(spec Spec) RunFunc { return m.runAliveHosts(spec) }

func (m Worker) RunDiscover(spec Spec) RunFunc { return m.runDiscover(spec) }

func (m Worker) RunChecks(hosts []string, templateIDs []string) RunFunc {
	return m.runChecks(hosts, templateIDs)
}

func (m Worker) RunPortChecks(service domain.Service, templateIDs []string) RunFunc {
	return m.runPortChecks(service, templateIDs)
}

func (m Worker) RunServiceChecks(services []domain.Service, templateIDs []string) RunFunc {
	return m.runServiceChecks(services, templateIDs)
}

func (m Worker) RunFull(hosts []string) RunFunc { return m.runFull(hosts) }

func (m Worker) CompileTemplates(ctx context.Context, ids []string) (templates []domain.Template, loadErrs []string) {
	return m.compileTemplates(ctx, ids)
}

func (m Worker) CompileTemplatesGrouped(ctx context.Context, ids []string) (templates []domain.Template, nseIDs []string, loadErrs []string) {
	return m.compileTemplatesGrouped(ctx, ids)
}
