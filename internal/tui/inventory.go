package tui

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

// hostInfo accumulates everything learned about one host across every run of
// the project, so results from separate background jobs land in one place
// instead of being replaced by "the last scan".
type hostInfo struct {
	services []domain.Service
	findings []domain.Finding
}

func serviceKey(s domain.Service) string {
	return fmt.Sprintf("%s/%s/%d", s.Host, s.Protocol, s.Port)
}

// serviceHostBucket decides which desk row a service belongs under. Service.Host
// is always the address actually dialed (discovery resolves a domain target to
// an IP before connecting), so grouping by it would split "example.com" into a
// separate, empty row from the IP that holds its actual ports. Service.Target
// carries the original scope entry when the code that produced it set it
// (workflow.Runner and the NSE runner both do); fall back to the job's single
// target when there was only one, and only use the raw resolved address as a
// last resort for older data that predates the Target field.
func serviceHostBucket(s domain.Service, jobTargets []string) string {
	if s.Target != "" {
		if h, err := discovery.TargetHost(s.Target); err == nil && h != "" {
			return h
		}
		// A subnet CIDR is a scan scope, not the host that owns this service.
		// Keep ports grouped under their discovered address when the run target
		// is a network range.
		if s.Host != "" {
			return s.Host
		}
		return s.Target
	}
	if s.Host != "" {
		return s.Host
	}
	if len(jobTargets) == 1 {
		return jobTargets[0]
	}
	return s.Host
}

// absorb folds one batch of services/findings into the inventory. jobTargets
// is the set of hosts the batch was produced for; pass nil when replaying
// history where that context is no longer available (correctness then relies
// on Service.Target, which every run since this field was introduced sets).
func (m *model) absorb(services []domain.Service, findings []domain.Finding, jobTargets []string, runID int64) {
	if m.inventory == nil {
		m.inventory = map[string]*hostInfo{}
	}
	for _, host := range jobTargets {
		m.ensureHost(host)
	}
	ipToHost := map[string]string{}
	for _, s := range services {
		if s.PortService == "" && m.cat != nil {
			s.PortService = discovery.PortServiceName(m.cat.LibraryDir(), s.Protocol, s.Port)
		}
		bucket := serviceHostBucket(s, jobTargets)
		if m.beforeHostReset(bucket, runID) {
			continue
		}
		m.ensureHost(bucket)
		hi := m.inventory[bucket]
		merged := false
		for i, existing := range hi.services {
			if serviceKey(existing) == serviceKey(s) {
				hi.services[i] = mergeService(existing, s)
				merged = true
				break
			}
		}
		if !merged {
			hi.services = append(hi.services, s)
		}
		if s.Host != "" {
			ipToHost[s.Host] = bucket
		}
	}
	for _, hi := range m.inventory {
		sort.Slice(hi.services, func(i, j int) bool { return hi.services[i].Port < hi.services[j].Port })
	}
	for _, f := range findings {
		if m.findingBeforeReset(f, runID) {
			continue
		}
		if strings.HasPrefix(f.TemplateID, "nmap/") {
			_, port, _, hasPort := findingEndpoint(f.MatchedAt)
			if !hasPort || port == 0 {
				var candidates []domain.Service
				addressHost, _ := discovery.TargetHost(f.Target)
				for _, s := range services {
					if addressHost == s.Host || addressHost == serviceHostBucket(s, jobTargets) {
						candidates = append(candidates, s)
					}
				}
				if len(candidates) == 1 {
					endpoint := net.JoinHostPort(candidates[0].Host, strconv.Itoa(candidates[0].Port))
					f.Target, f.MatchedAt = endpoint, "nse://"+endpoint+"/"+strings.TrimPrefix(f.TemplateID, "nmap/")
				}
			}
		}
		host := ""
		for ip, bucket := range ipToHost {
			if ip != "" && (strings.Contains(f.Target, ip) || strings.Contains(f.MatchedAt, ip)) {
				host = bucket
				break
			}
		}
		if host == "" {
			host = hostForFinding(f, jobTargets)
		}
		if host == "" && len(jobTargets) == 1 {
			host = jobTargets[0]
		}
		if host == "" {
			continue
		}
		m.ensureHost(host)
		m.inventory[host].findings = append(m.inventory[host].findings, f)
	}
	m.filterInventory()
}

func mergeService(old, new domain.Service) domain.Service {
	if new.Product != "" {
		old.Product = new.Product
	}
	if new.Version != "" {
		old.Version = new.Version
	}
	// Unconditional, matching Product/Version below: with loadInventory now
	// replaying run history oldest-to-newest, the most recent scan's
	// identification should always be the one that sticks, the same way a
	// rescan that finally recognizes a service (e.g. the active SMB probe
	// identifying a port a previous run left as "unknown"/"tcp"/empty) is
	// expected to correct the record instead of being silently discarded
	// because some older run already had *a* name there.
	if new.Name != "" {
		old.Name = new.Name
	}
	if new.PortService != "" {
		old.PortService = new.PortService
	}
	if new.Tunnel != "" {
		old.Tunnel = new.Tunnel
	}
	if old.Target == "" && new.Target != "" {
		old.Target = new.Target
	}
	return old
}

func hostForFinding(f domain.Finding, candidates []string) string {
	for _, host := range candidates {
		if host != "" && (strings.Contains(f.Target, host) || strings.Contains(f.MatchedAt, host)) {
			return host
		}
	}
	return ""
}

func (m *model) ensureHost(host string) {
	if host == "" {
		return
	}
	if m.inventory == nil {
		m.inventory = map[string]*hostInfo{}
	}
	if _, ok := m.inventory[host]; !ok {
		m.inventory[host] = &hostInfo{}
	}
}

// mergeResult folds one finished background job's result into the
// project-wide inventory and refreshes the persistent run history list shown
// on the History screen.
func (m *model) mergeResult(res engine.Result, targets []string) {
	m.absorb(res.Services, res.Findings, targets, res.RunID)
	m.rebuildHostOrder()
	m.history, _ = m.store.Runs(m.ctx, m.current.ID)
	if (m.screen == "finding-details" || m.screen == "project-results") && m.findingDetail != nil {
		index := m.findingIndex
		for i, f := range m.deskFindings() {
			if f.TemplateID == m.findingDetail.TemplateID && f.MatchedAt == m.findingDetail.MatchedAt && f.MatcherName == m.findingDetail.MatcherName {
				index = i
				break
			}
		}
		if !m.selectFinding(index) {
			m.findingDetail = nil
			m.findingIndex = 0
			m.findingOffset = 0
		}
	} else if m.screen == "project-results" {
		m.refreshProjectResultSelection()
	}
}

// rebuildHostOrder recomputes the numerically sorted host list shown in the
// desk's left column, including configured targets that have no results yet.
func (m *model) rebuildHostOrder() {
	m.hostOrder = m.hostBuckets()
	if m.hostNetwork != "" {
		m.hostOrder = m.networkHosts(m.hostNetwork)
	}
	if m.hostIndex >= len(m.hostOrder) {
		m.hostIndex = len(m.hostOrder) - 1
	}
}

// hostBuckets includes every visible machine, independently of the current scope.
func (m model) hostBuckets() []string {
	seen := map[string]bool{}
	order := make([]string, 0, len(m.inventory))
	for _, t := range m.current.Targets {
		if discovery.IsNetworkTarget(t) {
			continue
		}
		host, err := discovery.TargetHost(t)
		if err != nil {
			host = t
		}
		if !seen[host] && !m.excludedHost(host) {
			seen[host] = true
			order = append(order, host)
		}
	}
	for host := range m.inventory {
		if !seen[host] && !discovery.IsNetworkTarget(host) && !m.excludedHost(host) {
			order = append(order, host)
		}
	}
	sort.Slice(order, func(i, j int) bool { return hostOrderLess(order[i], order[j]) })
	return order
}

func hostOrderLess(a, b string) bool {
	ipA, ipB := net.ParseIP(a), net.ParseIP(b)
	if ipA != nil && ipB != nil {
		a4, b4 := ipA.To4(), ipB.To4()
		if (a4 != nil) != (b4 != nil) {
			return a4 != nil
		}
		if a4 != nil {
			return bytes.Compare(a4, b4) < 0
		}
		return bytes.Compare(ipA.To16(), ipB.To16()) < 0
	}
	if ipA != nil {
		return true
	}
	if ipB != nil {
		return false
	}
	aLower, bLower := strings.ToLower(a), strings.ToLower(b)
	if aLower == bLower {
		return a < b
	}
	return aLower < bLower
}

func (m model) networkTargets() []string {
	var out []string
	for _, target := range m.current.Targets {
		if discovery.IsNetworkTarget(target) {
			out = append(out, target)
		}
	}
	return out
}

func (m model) networkHostCount(cidr string) int {
	return len(m.networkHosts(cidr))
}

func (m model) networkHosts(cidr string) []string {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var out []string
	for _, host := range m.hostBuckets() {
		match := network.Contains(net.ParseIP(host))
		for _, service := range m.servicesFor(host) {
			match = match || network.Contains(net.ParseIP(service.Host))
		}
		if match {
			out = append(out, host)
		}
	}
	return out
}

func (m *model) openHostScope(cidr string) {
	m.hostNetwork = cidr
	m.preferredPort, m.preferredProtocol = 0, ""
	m.selectedHosts = nil
	m.hostIndex, m.serviceIndex, m.findingIndex, m.focusCol = -1, -1, 0, 0
	m.rebuildHostOrder()
	if len(m.hostOrder) > 0 {
		m.hostIndex = 0
	}
	m.screen = "desk"
}

// loadInventory rebuilds the whole project inventory from stored run
// history, used right after opening a project.
func (m *model) loadInventory() {
	m.exclusions, _ = m.store.InventoryExclusions(m.ctx, m.current.ID)
	m.inventoryResets, _ = m.store.InventoryResets(m.ctx, m.current.ID)
	m.inventory = map[string]*hostInfo{}
	cachedNames, _ := m.store.HostNames(m.ctx, m.current.ID)
	m.hostNames = make(map[string][]string)
	m.dnsPinned = make(map[string]bool)
	m.dnsChecked = make(map[string]time.Time)
	for host, cached := range cachedNames {
		m.hostNames[host] = cached.Names
		m.dnsPinned[host] = cached.Server != ""
		m.dnsChecked[host] = cached.CheckedAt
	}
	// m.history is newest-first (storage.Runs orders by id DESC), but
	// mergeService lets a non-empty Product/Version/Name unconditionally win
	// over whatever is already there — so replaying in that order let an
	// OLDER run's stale (but non-empty) field clobber a newer run's correct
	// one. Replay oldest-to-newest so the most recent scan is always the one
	// left standing for any field both runs identified.
	for i := len(m.history) - 1; i >= 0; i-- {
		run := m.history[i]
		m.absorb(run.Services, run.Findings, nil, run.ID)
	}
	m.rebuildHostOrder()
}

// targetBuckets returns normalized host names for all individual machines.
// CIDR ranges live in the separate subnet window and are never passed as hosts.
func (m model) targetBuckets() []string {
	return append([]string(nil), m.hostOrder...)
}

func (m model) selectedTargetHosts() []string {
	var out []string
	for _, host := range m.hostOrder {
		if m.selectedHosts[host] {
			out = append(out, host)
		}
	}
	return out
}

func (m model) currentHost() string {
	if m.hostIndex < 0 || m.hostIndex >= len(m.hostOrder) {
		return ""
	}
	return m.hostOrder[m.hostIndex]
}

func (m model) servicesFor(host string) []domain.Service {
	if hi, ok := m.inventory[host]; ok {
		return hi.services
	}
	return nil
}

func (m model) findingsFor(host string) []domain.Finding {
	if hi, ok := m.inventory[host]; ok {
		return groupedProjectResults(orderedResults(hi.findings))
	}
	return nil
}

func (m model) findingsForService(host string, s domain.Service) []domain.Finding {
	return groupedProjectResults(orderedResults(m.rawFindingsForService(host, s)))
}

func (m model) rawFindingsForService(host string, s domain.Service) []domain.Finding {
	allowed := map[string]bool{strings.ToLower(s.Host): true, strings.ToLower(host): true}
	if target, err := discovery.TargetHost(s.Target); err == nil {
		allowed[strings.ToLower(target)] = true
	}
	var out []domain.Finding
	var findings []domain.Finding
	if h := m.inventory[host]; h != nil {
		findings = h.findings
	}
	for _, f := range findings {
		if strings.HasPrefix(f.TemplateID, "adscan-") && allowed[strings.ToLower(f.MatchedAt)] && adFindingOnPort(f, s) {
			out = append(out, f)
			continue
		}
		if coercionResult(f) && s.Port == 445 && s.Protocol != "udp" && allowed[strings.ToLower(f.Target)] {
			out = append(out, f)
			continue
		}
		for _, address := range []string{f.MatchedAt, f.Target} {
			name, port, scheme, ok := findingEndpoint(address)
			if !ok {
				continue
			}
			if port == s.Port && allowed[strings.ToLower(name)] && !(s.Protocol == "udp" && (scheme == "http" || scheme == "https")) {
				out = append(out, f)
			}
			// A precise matched endpoint takes precedence over a generic target.
			break
		}
	}
	return orderedResults(out)
}

func findingEndpoint(address string) (string, int, string, bool) {
	if strings.Contains(address, "://") {
		u, err := url.Parse(address)
		if err != nil || u.Hostname() == "" {
			return "", 0, "", false
		}
		port, _ := strconv.Atoi(u.Port())
		if port == 0 {
			if u.Scheme == "http" {
				port = 80
			} else if u.Scheme == "https" {
				port = 443
			}
		}
		return u.Hostname(), port, u.Scheme, port > 0
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, "", false
	}
	port, err := strconv.Atoi(portText)
	return host, port, "", err == nil && port > 0
}

// knownServices returns every previously discovered service for the given
// hosts (used to target Nuclei/NSE actions without re-running discovery).
func (m model) knownServices(hosts []string) []domain.Service {
	var out []domain.Service
	for _, host := range hosts {
		out = append(out, m.servicesFor(host)...)
	}
	return out
}

// knownWebTargets returns HTTP(S) URLs for every previously discovered web
// service on the given hosts, plus any target that was itself an explicit
// http(s) URL.
func (m model) knownWebTargets(hosts []string) []string {
	set := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !set[u] {
			set[u] = true
			out = append(out, u)
		}
	}
	for _, host := range hosts {
		for _, s := range m.servicesFor(host) {
			if u, ok := discovery.WebURL(s); ok {
				add(u)
			}
		}
	}
	for _, t := range m.current.Targets {
		lower := strings.ToLower(t)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			for _, host := range hosts {
				if strings.Contains(t, host) {
					add(t)
				}
			}
		}
	}
	return out
}

func (m model) hostSummary(host string) (ports, findings int) {
	return len(m.servicesFor(host)), len(m.findingsFor(host))
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func portProtocol(protocol string) string {
	if protocol == "" {
		return "tcp"
	}
	return strings.ToLower(protocol)
}
func (m *model) rememberSelectedPort(services []domain.Service) {
	if m.hostIndex >= 0 && m.serviceIndex >= 0 && m.serviceIndex < len(services) {
		service := services[m.serviceIndex]
		m.preferredPort, m.preferredProtocol = service.Port, portProtocol(service.Protocol)
	}
}
func (m *model) restoreSelectedPort() {
	m.serviceIndex = -1
	services := m.servicesFor(m.currentHost())
	if m.preferredPort == 0 {
		return
	}
	for i, s := range services {
		if s.Port == m.preferredPort && portProtocol(s.Protocol) == m.preferredProtocol {
			m.serviceIndex = i
			return
		}
	}
}
func (m model) selectedPortMissing() bool {
	return m.hostIndex >= 0 && m.preferredPort > 0 && m.serviceIndex < 0
}

// AD inventory is saved against a host, not a matcher URL. Associate only
// relevant AD facts with each service, including results saved by older builds.
func adFindingOnPort(f domain.Finding, s domain.Service) bool {
	if portProtocol(s.Protocol) != "tcp" {
		return false
	}
	ldap := s.Port == 389 || s.Port == 636 || s.Port == 3268 || s.Port == 3269
	switch f.TemplateID {
	case "adscan-role-domain-controller", "adscan-role-domain-controller-candidate":
		return ldap || s.Port == 88 || s.Port == 464
	case "adscan-role-global-catalog":
		return s.Port == 3268 || s.Port == 3269
	case "adscan-role-dns", "adscan-dns-srv":
		return s.Port == 53
	case "adscan-role-certificate-services":
		return s.Port == 80 || s.Port == 443
	case "adscan-role-ad-web-services":
		return s.Port == 9389
	case "adscan-role-windows-host":
		return s.Port == 135 || s.Port == 139 || s.Port == 445 || s.Port == 3389
	case "adscan-smb-anonymous-access":
		return s.Port == 445
	case "adscan-recon-summary":
		return false
	default:
		return ldap
	}
}
