package tui

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/adscan"
)

type adAccessIdentityDetected struct {
	project      int64
	generation   int
	host, domain string
	nodes        []adscan.Host
	errors       []string
}

func adIdentityLDAPPort(host adscan.Host) int {
	for _, want := range []int{636, 389} {
		for _, port := range host.Ports {
			if port == want {
				return port
			}
		}
	}
	return 0
}

func (m *model) prefillADAccessIdentity() {
	m.adAccessNodes, m.adAccessNodesProject = m.projectADInventory().Hosts, m.current.ID
	m.chooseADAccessIdentity(m.adAccessNodes)
	if m.adAccessDomain == "" && m.adAccessHint == "" && len(m.adScanDNS.Domains) == 1 {
		if m.adAccessManualHost == "" {
			m.adAccessDomain = m.adScanDNS.Domains[0]
		}
	}
}

func (m *model) chooseADAccessIdentity(nodes []adscan.Host) {
	if m.adAccessManualHost != "" {
		m.adAccessHost = m.adAccessManualHost
		for _, host := range nodes {
			if host.Address != m.adAccessManualHost {
				continue
			}
			if m.adAccessDomain == "" {
				m.adAccessDomain = strings.TrimSuffix(strings.ToLower(host.Domain), ".")
			}
			if port := adIdentityLDAPPort(host); port != 0 {
				m.adAccessLDAPPort, m.adBloodHoundPort = port, port
			}
		}
		return
	}
	var domains []string
	selectedDomain := ""
	for _, host := range nodes {
		d := strings.TrimSuffix(strings.ToLower(host.Domain), ".")
		if d == "" {
			continue
		}
		domains = append(domains, d)
		if host.Address == m.currentHost() {
			selectedDomain = d
		}
	}
	domains = uniqueStrings(domains)
	sort.Strings(domains)
	if m.adAccessDomain == "" {
		if selectedDomain != "" {
			m.adAccessDomain = selectedDomain
		} else if len(domains) == 1 {
			m.adAccessDomain = domains[0]
		} else if len(domains) > 1 {
			m.adAccessHint = "Домены: " + strings.Join(domains, ", ") + " · d выбрать"
			return
		}
	}
	if m.adAccessDomain == "" {
		return
	}
	var chosen *adscan.Host
	for i := range nodes {
		host := &nodes[i]
		if !strings.EqualFold(host.Domain, m.adAccessDomain) || adIdentityLDAPPort(*host) == 0 {
			continue
		}
		if chosen == nil || (!chosen.DCConfirmed && host.DCConfirmed) {
			chosen = host
		}
		if host.Address == m.currentHost() && host.DCConfirmed {
			chosen = host
			break
		}
	}
	if chosen != nil {
		m.adAccessHost = chosen.Address
		m.adAccessAutoHost = chosen.Address
		port := adIdentityLDAPPort(*chosen)
		if port == 389 || port == 636 {
			m.adAccessLDAPPort, m.adBloodHoundPort = port, port
		}
	}
}

func (m *model) detectADAccessIdentityCmd() tea.Cmd {
	if m.adAccessDomain != "" && m.adAccessHost != "" {
		return nil
	}
	if strings.HasPrefix(m.adAccessHint, "Домены:") {
		return nil
	}
	var candidates []adscan.Host
	if m.adAccessManualHost != "" {
		host := adscan.Host{Address: m.adAccessManualHost, Ports: []int{389}}
		for _, node := range m.projectADInventory().Hosts {
			if node.Address == host.Address && adIdentityLDAPPort(node) != 0 {
				host = node
				break
			}
		}
		candidates = append(candidates, host)
	} else {
		for _, host := range m.projectADInventory().Hosts {
			if adIdentityLDAPPort(host) != 0 {
				candidates = append(candidates, host)
			}
		}
	}
	if len(candidates) == 0 {
		m.adAccessHint = "Домен не найден: запусти AD-разведку или укажи хост/домен вручную."
		return nil
	}
	limited := len(candidates) > 8
	selected := m.currentHost()
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Address == selected && candidates[j].Address != selected })
	candidates = candidates[:min(8, len(candidates))]
	snapshot := adAccessIdentityDetected{project: m.current.ID, generation: m.adAccessGeneration, host: m.adAccessHost, domain: m.adAccessDomain}
	m.adAccessAutoBusy, m.adAccessHint = true, "Читаю RootDSE найденных LDAP-узлов…"
	parent := m.ctx
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(parent, 6*time.Second)
		defer cancel()
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)
		for _, candidate := range candidates {
			wg.Add(1)
			go func(host adscan.Host) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				probeCtx, stop := context.WithTimeout(ctx, 3*time.Second)
				defer stop()
				// Plain RootDSE carries no credentials; prefer 389 when known open.
				port := adIdentityLDAPPort(host)
				for _, p := range host.Ports {
					if p == 389 {
						port = p
						break
					}
				}
				node, err := adscan.DiscoverLDAPIdentity(probeCtx, host.Address, port)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					snapshot.errors = append(snapshot.errors, err.Error())
				} else {
					snapshot.nodes = append(snapshot.nodes, node)
				}
			}(candidate)
		}
		wg.Wait()
		sort.Slice(snapshot.nodes, func(i, j int) bool { return snapshot.nodes[i].Address < snapshot.nodes[j].Address })
		if limited {
			snapshot.errors = append(snapshot.errors, "прочитаны только первые 8 LDAP-узлов")
		}
		return snapshot
	}
}

func (m *model) applyADAccessIdentity(result adAccessIdentityDetected) {
	if result.project != m.current.ID || result.generation != m.adAccessGeneration || result.host != m.adAccessHost || result.domain != m.adAccessDomain {
		return
	}
	m.adAccessAutoBusy, m.adAccessHint = false, ""
	m.adAccessNodes, m.adAccessNodesProject = result.nodes, result.project
	m.chooseADAccessIdentity(result.nodes)
	if m.adAccessHint != "" {
		return
	}
	if m.adAccessDomain == "" {
		m.adAccessHint = "RootDSE не раскрыл домен; укажи его вручную (d)."
		if len(result.errors) > 0 {
			m.adAccessHint = "Домен не определён: " + result.errors[0]
		}
		return
	}
	if m.adAccessHost == "" {
		m.adAccessHint = "Для домена " + m.adAccessDomain + " LDAP-контроллер не найден; h указать вручную."
		return
	}
	m.adAccessHint = "Домен определён через LDAP RootDSE."
	if m.adAccessManualHost != "" {
		if err := m.store.SetADController(m.ctx, m.current.ID, m.adAccessManualHost, m.adAccessDomain); err != nil {
			m.message = "Не удалось сохранить контроллер: " + err.Error()
		}
	}
	if len(result.errors) > 0 {
		m.adAccessHint += " Часть узлов не проверена."
	}
}
