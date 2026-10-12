package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wscan/internal/catalog"
	"wscan/internal/domain"
	"wscan/internal/nse"
)

// nseRunner builds the NSE runner config from the current project,
// using the native Lua engine with explicit ports and network timeout.
func (m Worker) nseRunner() *nse.Runner {
	timeout := time.Duration(m.current.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	args := nse.DefaultBruteArgs(m.current.RPS, m.current.Concurrency)
	guesses := m.current.LockoutMaxAttempts
	if guesses <= 0 {
		guesses = domain.DefaultLockoutMaxAttempts
	}
	args["brute.guesses"] = strconv.Itoa(min(guesses, 100))
	return nse.New(m.cat.LibraryDir(), nse.Config{
		Timeout:              timeout,
		Complete:             false,
		SelectedServicesOnly: true,
		RPS:                  m.current.RPS,
		Args:                 args,
	})
}

func hostNameIfDomain(host string) string {
	if net.ParseIP(host) == nil {
		return host
	}
	return ""
}

func portInfos(services []domain.Service) []nse.PortInfo {
	out := make([]nse.PortInfo, 0, len(services))
	for _, s := range services {
		out = append(out, nse.PortInfo{
			Number:   s.Port,
			Protocol: s.Protocol,
			State:    "open",
			Service:  s.Name,
			Product:  s.Product,
			Version:  s.Version,
			Tunnel:   s.Tunnel,
		})
	}
	return out
}

func nseFinding(host string, r nse.ScriptResult) domain.Finding {
	target := host
	matched := "nse://" + host
	if r.Port != 0 {
		target = fmt.Sprintf("%s:%d", host, r.Port)
		matched = fmt.Sprintf("nse://%s:%d/%s", host, r.Port, r.ScriptID)
	}
	return domain.Finding{
		TemplateID: "nmap/" + r.ScriptID,
		Name:       r.ScriptID,
		Severity:   nse.ScriptSeverity(r.ScriptID, r.Output),
		Target:     target,
		MatchedAt:  matched,
		Evidence:   r.Output,
		Risk:       "active",
		Time:       time.Now().UTC(),
	}
}

// runNmapScriptsOn runs the chosen NSE scripts against one host's services via
// the native NSE engine and returns findings + errors.
func (m Worker) runNmapScriptsOn(ctx context.Context, runner *nse.Runner, displayHost string, hi nse.HostInfo, ports []nse.PortInfo, scriptIDs []string, emit Reporter) ([]domain.Finding, []string) {
	var findings []domain.Finding
	var errs []string
	for i, id := range scriptIDs {
		if ctx.Err() != nil {
			break
		}
		if emit != nil {
			emit("NSE: "+displayHost, i, len(scriptIDs))
		}
		if nseDenialOfServiceScript(m.entries, id) {
			if emit != nil {
				emit("NSE: " + id + " — пропущено: проверки на отказ в обслуживании отключены")
			}
			continue
		}
		if !m.current.AllowExploit && nseRequiresOptInScript(m.entries, id) {
			if emit != nil {
				emit("NSE: " + id + " — пропущено: интенсивные проверки требуют отдельного подтверждения")
			}
			continue
		}
		if _, err := m.cat.Load(ctx, id); err != nil {
			errs = append(errs, id+": "+err.Error())
			continue
		}
		if !m.current.AllowExploit && (strings.HasSuffix(id, "/ms-sql-query.nse") || strings.HasSuffix(id, "/ms-sql-xp-cmdshell.nse") || strings.HasSuffix(id, "/ms-sql-dump-hashes.nse") || strings.HasSuffix(id, "/ms-sql-config.nse")) {
			errs = append(errs, id+": требуется AllowExploit")
			continue
		}
		path := filepath.Join(m.cat.LibraryDir(), filepath.FromSlash(id))
		var selectedPorts []nse.PortInfo
		for _, port := range ports {
			service := domain.Service{Host: hi.IP, Port: port.Number, Protocol: port.Protocol, Name: port.Service}
			matching, _ := portCompatibleTemplateIDs(m.entries, service, []string{id})
			if len(matching) > 0 {
				selectedPorts = append(selectedPorts, port)
			}
		}
		if len(ports) > 0 && len(selectedPorts) == 0 {
			if emit != nil {
				emit("NSE: " + id + " — пропущено: проверка относится к другому типу БД")
			}
			continue
		}
		started := time.Now()
		if emit != nil {
			emit(fmt.Sprintf("NSE: %s · %s — запуск (лимит %s)", displayHost, id, runner.ScriptTimeLimit()), i, len(scriptIDs))
		}
		results, ran, err := runner.Run(ctx, path, hi, selectedPorts)
		if emit != nil {
			status := "завершён"
			switch {
			case ctx.Err() != nil:
				status = "отменён"
			case errors.Is(err, context.DeadlineExceeded):
				status = "таймаут"
			case err != nil:
				status = "ошибка"
			case !ran:
				status = "пропущен"
			}
			message := fmt.Sprintf("NSE: %s · %s — %s за %s", displayHost, id, status, time.Since(started).Round(time.Millisecond))
			if err != nil {
				message += ": " + err.Error()
			}
			emit(message, i+1, len(scriptIDs))
		}
		if err != nil {
			errs = append(errs, id+": "+err.Error())
		}
		if !ran {
			if err == nil && emit != nil {
				emit("NSE: " + id + " — пропущено: правило не подходит к выбранным сервисам")
			}
			continue
		}
		for _, r := range results {
			if nse.OutputIsNoise(r.ScriptID, r.Output) {
				continue
			}
			if nse.OutputIsError(r.Output) {
				errs = append(errs, id+": "+r.Output)
				continue
			}
			findings = append(findings, nseFinding(displayHost, r))
		}
	}
	if emit != nil && ctx.Err() == nil {
		emit("NSE: "+displayHost, len(scriptIDs), len(scriptIDs))
	}
	return findings, errs
}

func nseDenialOfServiceScript(entries []catalog.Entry, id string) bool {
	// smb-flood is an explicit DoS script and must never run as part of a
	// normal service-check batch. The catalog metadata rule covers other NSE
	// scripts marked with the same category.
	if filepath.Base(id) == "smb-flood.nse" {
		return true
	}
	for _, entry := range entries {
		if entry.Path != id {
			continue
		}
		category := strings.ToLower(entry.Category + " " + entry.Type)
		return strings.Contains(category, "dos") || strings.Contains(category, "отказ в обслуживании")
	}
	return false
}

func nseRequiresOptInScript(entries []catalog.Entry, id string) bool {
	for _, entry := range entries {
		if entry.Path == id {
			return catalog.Impact(entry) == catalog.ImpactStrong
		}
	}
	return false
}

// runNmapScripts runs the scripts against the inventory's known services for
// the given hosts (use after a separate Discover run has populated them).
func (m Worker) runNmapScripts(ctx context.Context, hosts, scriptIDs []string, emit Reporter) ([]domain.Finding, []string) {
	var services []domain.Service
	for _, host := range hosts {
		services = append(services, m.servicesFor(host)...)
	}
	return m.runNmapScriptsForServices(ctx, services, scriptIDs, emit)
}

// runNmapScriptsForServices groups an explicit service slice by host bucket and
// runs the scripts against each. Used by the full scan, where freshly
// discovered services are not yet in the inventory.
func (m Worker) runNmapScriptsForServices(ctx context.Context, services []domain.Service, scriptIDs []string, emit Reporter) ([]domain.Finding, []string) {
	runner := m.nseRunner()
	groups := map[string][]domain.Service{}
	displays := map[string]string{}
	var order []string
	for _, s := range services {
		display := serviceHostBucket(s, nil)
		bucket := display + "\x00" + s.Host
		displays[bucket] = display
		if _, ok := groups[bucket]; !ok {
			order = append(order, bucket)
		}
		groups[bucket] = append(groups[bucket], s)
	}
	var findings []domain.Finding
	var errs []string
	for _, host := range order {
		svcs := groups[host]
		display := displays[host]
		hi := nse.HostInfo{Name: hostNameIfDomain(display), IP: svcs[0].Host}
		f, e := m.runNmapScriptsOn(ctx, runner, display, hi, portInfos(svcs), scriptIDs, emit)
		findings = append(findings, f...)
		errs = append(errs, e...)
	}
	return findings, errs
}

func NSEFinding(host string, r nse.ScriptResult) domain.Finding { return nseFinding(host, r) }

func HostNameIfDomain(host string) string { return hostNameIfDomain(host) }

func PortInfos(services []domain.Service) []nse.PortInfo { return portInfos(services) }

func NSEDenialOfServiceScript(entries []catalog.Entry, id string) bool {
	return nseDenialOfServiceScript(entries, id)
}

func NSERequiresOptInScript(entries []catalog.Entry, id string) bool {
	return nseRequiresOptInScript(entries, id)
}

func (m Worker) NseRunner() *nse.Runner { return m.nseRunner() }

func (m Worker) RunNmapScriptsOn(ctx context.Context, runner *nse.Runner, displayHost string, hi nse.HostInfo, ports []nse.PortInfo, scriptIDs []string, emit Reporter) ([]domain.Finding, []string) {
	return m.runNmapScriptsOn(ctx, runner, displayHost, hi, ports, scriptIDs, emit)
}

func (m Worker) RunNmapScripts(ctx context.Context, hosts, scriptIDs []string, emit Reporter) ([]domain.Finding, []string) {
	return m.runNmapScripts(ctx, hosts, scriptIDs, emit)
}

func (m Worker) RunNmapScriptsForServices(ctx context.Context, services []domain.Service, scriptIDs []string, emit Reporter) ([]domain.Finding, []string) {
	return m.runNmapScriptsForServices(ctx, services, scriptIDs, emit)
}
