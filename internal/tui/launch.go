package tui

import (
	"context"
	"fmt"
	"strings"

	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
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

// splitFamilies separates selected template IDs into Nuclei templates and Nmap
// NSE scripts so each goes to its own engine.

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

// runChecks runs the selected checks (Nuclei templates and/or Nmap NSE scripts,
// mixed) against already-known services on the given hosts. One job, one run,
// live progress — the user never thinks about which engine runs what.

// runPortChecks restricts the selected checks to exactly one discovered service.

// runFull replays the project's configured default checks together with a fresh
// discovery pass.

// compileTemplates loads and parses the given Nuclei template IDs for the
// selected engine. Complete documents are retained for Nuclei; without it,
// native parser limitations are reported in loadErrs. NSE ids are ignored here.

// compileTemplatesGrouped is compileTemplates plus NSE id separation, used by
// the full-scan action which mixes both families.
