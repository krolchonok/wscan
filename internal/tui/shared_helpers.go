package tui

import (
	"wscan/internal/adscan"
	"wscan/internal/app"
	"wscan/internal/catalog"
	"wscan/internal/domain"
	"wscan/internal/nse"
)

func adDNSFindings(cidr string, records []adscan.SRVRecord) []domain.Finding {
	return app.ADDNSFindings(cidr, records)
}
func adReconSummary(cidr string, result adscan.Result, findings []domain.Finding) domain.Finding {
	return app.ADReconSummary(cidr, result, findings)
}
func adEvidenceFinding(cidr, host, key, name, evidence, risk string) domain.Finding {
	return app.ADEvidenceFinding(cidr, host, key, name, evidence, risk)
}
func adProjectName(cidr string, result adscan.Result) string { return app.ADProjectName(cidr, result) }
func adRoleKey(role string) string                           { return app.ADRoleKey(role) }
func adPortNames(port int) (name, description string)        { return app.ADPortNames(port) }
func accountSample(names []string) string                    { return app.AccountSample(names) }
func roleContains(roles []string, role string) bool          { return app.RoleContains(roles, role) }
func containsInt(values []int, value int) bool               { return app.ContainsInt(values, value) }
func portCompatibleTemplateIDs(entries []catalog.Entry, service domain.Service, ids []string) (compatible, skipped []string) {
	return app.PortCompatibleTemplateIDs(entries, service, ids)
}
func servicesCompatibleTemplateIDs(entries []catalog.Entry, services []domain.Service, ids []string) (compatible, skipped []string) {
	return app.ServicesCompatibleTemplateIDs(entries, services, ids)
}
func portURL(s domain.Service) string                           { return app.PortURL(s) }
func splitFamilies(ids []string) (nuclei, nse []string)         { return app.SplitFamilies(ids) }
func nseFinding(host string, r nse.ScriptResult) domain.Finding { return app.NSEFinding(host, r) }
func hostNameIfDomain(host string) string                       { return app.HostNameIfDomain(host) }
func portInfos(services []domain.Service) []nse.PortInfo        { return app.PortInfos(services) }
func nseDenialOfServiceScript(entries []catalog.Entry, id string) bool {
	return app.NSEDenialOfServiceScript(entries, id)
}
func nseRequiresOptInScript(entries []catalog.Entry, id string) bool {
	return app.NSERequiresOptInScript(entries, id)
}
