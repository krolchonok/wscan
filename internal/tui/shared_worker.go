package tui

import (
	"context"
	"path/filepath"
	"sort"
	"wscan/internal/adscan"
	"wscan/internal/app"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/nse"
)

func (m model) sharedWorker() app.Worker {
	var services []domain.Service
	var keys []string
	for h := range m.inventory {
		keys = append(keys, h)
	}
	sort.Strings(keys)
	for _, h := range keys {
		if m.inventory[h] != nil {
			services = append(services, m.inventory[h].services...)
		}
	}
	return app.NewWorker(m.store, m.cat, m.scanner, m.current, m.entries, services, m.adScanNewProject, m.adScanDNS).WithADExportDir(filepath.Join(m.appDir, "exports", "ad"))
}
func sharedSpec(s launchSpec) app.Spec {
	return app.Spec{Kind: s.kind, Label: s.label, Hosts: s.hosts, TemplateIDs: s.templateIDs, Service: s.service, Services: s.services, DNSServer: s.dnsServer, DiscPorts: s.discPorts, DiscUDPPorts: s.discUDPPorts, DiscAllPorts: s.discAllPorts, DiscSkipTCP: s.discSkipTCP, DiscNoVersion: s.discNoVersion, DiscOnlyKnown: s.discOnlyKnown, DiscNoPing: s.discNoPing}
}
func (m model) runADScan(ctx context.Context, cidr string, emit progressReporter) (engine.Result, *adscan.Result, int64, string, error) {
	return m.sharedWorker().RunADScan(ctx, cidr, emit)
}
func (m model) adResultProject(ctx context.Context, cidr string, result adscan.Result) (int64, string, error) {
	return m.sharedWorker().AdResultProject(ctx, cidr, result)
}
func (m model) runAliveHosts(s launchSpec) runFunc {
	return m.sharedWorker().RunAliveHosts(sharedSpec(s))
}
func (m model) runDiscover(s launchSpec) runFunc      { return m.sharedWorker().RunDiscover(sharedSpec(s)) }
func (m model) runPTR(s launchSpec) runFunc           { return m.sharedWorker().RunPTR(sharedSpec(s)) }
func (m model) runChecks(hosts, ids []string) runFunc { return m.sharedWorker().RunChecks(hosts, ids) }
func (m model) runFull(hosts []string) runFunc        { return m.sharedWorker().RunFull(hosts) }
func (m model) runPortChecks(s domain.Service, ids []string) runFunc {
	return m.sharedWorker().RunPortChecks(s, ids)
}
func (m model) runServiceChecks(s []domain.Service, ids []string) runFunc {
	return m.sharedWorker().RunServiceChecks(s, ids)
}
func (m model) compileTemplates(ctx context.Context, ids []string) ([]domain.Template, []string) {
	return m.sharedWorker().CompileTemplates(ctx, ids)
}
func (m model) compileTemplatesGrouped(ctx context.Context, ids []string) ([]domain.Template, []string, []string) {
	return m.sharedWorker().CompileTemplatesGrouped(ctx, ids)
}
func (m model) nseRunner() *nse.Runner { return m.sharedWorker().NseRunner() }
func (m model) runNmapScriptsOn(ctx context.Context, r *nse.Runner, h string, hi nse.HostInfo, ps []nse.PortInfo, ids []string, e progressReporter) ([]domain.Finding, []string) {
	return m.sharedWorker().RunNmapScriptsOn(ctx, r, h, hi, ps, ids, e)
}
func (m model) runNmapScripts(ctx context.Context, hs, ids []string, e progressReporter) ([]domain.Finding, []string) {
	return m.sharedWorker().RunNmapScripts(ctx, hs, ids, e)
}
func (m model) runNmapScriptsForServices(ctx context.Context, ss []domain.Service, ids []string, e progressReporter) ([]domain.Finding, []string) {
	return m.sharedWorker().RunNmapScriptsForServices(ctx, ss, ids, e)
}
