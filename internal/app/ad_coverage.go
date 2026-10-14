package app

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"wscan/internal/adscan"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/nse"
)

var smbUserLine = regexp.MustCompile(`(?m)^\s*(?:[|_ ]*)?([^\\\r\n]+)\\([^\s(]+)\s+\(RID:`)
var smbUserSummary = regexp.MustCompile(`(?m)Domain:\s*([^;\r\n]+);\s*Users:\s*([^\r\n]+)`)

func samrNames(output, realm string) []string {
	var users []string
	for _, m := range smbUserLine.FindAllStringSubmatch(output, -1) {
		if strings.EqualFold(strings.TrimSpace(m[1]), realm) && !strings.HasSuffix(m[2], "$") {
			users = append(users, m[2])
		}
	}
	for _, m := range smbUserSummary.FindAllStringSubmatch(output, -1) {
		if strings.EqualFold(strings.TrimSpace(m[1]), realm) {
			for _, u := range strings.Split(m[2], ",") {
				u = strings.TrimSpace(u)
				if u != "" && !strings.HasSuffix(u, "$") {
					users = append(users, u)
				}
			}
		}
	}
	return uniqueStrings(users)
}

func (m Worker) collectADCoverage(ctx context.Context, r *adscan.Result, emit Reporter) {
	cover := func(host string, port int, id, state, evidence string) {
		r.Coverage = append(r.Coverage, domain.CheckCoverage{Host: host, Port: port, CheckID: id, State: state, Evidence: evidence})
	}
	for i := range r.Hosts {
		if ctx.Err() != nil {
			return
		}
		host := &r.Hosts[i]
		for _, access := range host.SMBAccess {
			b, _ := json.Marshal(access)
			cover(host.Address, 445, "smb-"+access.Mode, access.State, string(b))
		}
		if containsInt(host.Ports, 445) {
			if emit != nil {
				emit("SMB identity / SAMR: " + host.Address)
			}
			id, err := discovery.ProbeSMBIdentity(ctx, host.Address, 445, 4*time.Second)
			if err != nil {
				cover(host.Address, 445, "smb-identity", "error", err.Error())
			} else {
				b, _ := json.Marshal(id)
				cover(host.Address, 445, "smb-identity", "observed", string(b))
				if host.HostName == "" {
					host.HostName = id.DNSComputerName
					if host.HostName == "" {
						host.HostName = id.ComputerName
					}
				}
				if host.Domain == "" {
					host.Domain = id.DNSDomainName
				}
				for _, fact := range []adscan.IdentityFact{{Kind: "hostname", Value: id.DNSComputerName, Source: "SMB NTLM challenge"}, {Kind: "domain", Value: id.DNSDomainName, Source: "SMB NTLM challenge"}} {
					if fact.Value != "" {
						host.Identity = append(host.Identity, fact)
					}
				}
			}
			// SAMR enumeration only, no LSA RID range, dictionary or smb-brute dependency.
			runner := nse.New(m.cat.LibraryDir(), nse.Config{Timeout: 3 * time.Second, ScriptTimeout: 8 * time.Second, RPS: 2, SelectedServicesOnly: true, Args: map[string]string{"samronly": "true", "smbnoguest": "true"}})
			results, ran, err := runner.Run(ctx, filepath.Join(m.cat.LibraryDir(), "nmap/scripts/smb-enum-users.nse"), nse.HostInfo{IP: host.Address}, []nse.PortInfo{{Number: 445, Protocol: "tcp", State: "open", Service: "microsoft-ds"}})
			state, evidence := "incomplete", "SAMR не вернул список; имена неизвестны"
			if err != nil {
				state, evidence = "error", err.Error()
			} else if !ran {
				state, evidence = "skipped", "SAMR не запущен"
			} else if len(results) > 0 {
				evidence = results[0].Output
				if strings.Contains(strings.ToUpper(evidence), "ACCESS_DENIED") {
					state = "denied"
				} else if nse.OutputIsError(evidence) {
					state = "error"
				} else {
					state = "observed"
					if host.DCConfirmed && id.DomainName != "" {
						host.SMBUsers = samrNames(evidence, id.DomainName)
					}
				}
			}
			cover(host.Address, 445, "samr-users", state, evidence)
		}
		if containsInt(host.Ports, 53) {
			if host.Domain == "" {
				cover(host.Address, 53, "dns-axfr", "skipped", "DNS-зона неизвестна")
				continue
			}
			report, err := adscan.AuditDNS(ctx, host.Address, host.Domain, 53, 4*time.Second)
			for _, check := range report.Checks {
				cover(host.Address, 53, check.ID, check.State, check.Evidence)
			}
			if err != nil {
				cover(host.Address, 53, "dns-audit", "error", err.Error())
			}
		}
	}
}

func adCoverageFindings(scope string, coverage []domain.CheckCoverage) []domain.Finding {
	groups := map[string][]domain.CheckCoverage{}
	var hosts []string
	for _, c := range coverage {
		if _, ok := groups[c.Host]; !ok {
			hosts = append(hosts, c.Host)
		}
		groups[c.Host] = append(groups[c.Host], c)
	}
	sort.Strings(hosts)
	var findings []domain.Finding
	for _, host := range hosts {
		var lines []string
		for _, c := range groups[host] {
			lines = append(lines, fmt.Sprintf("%s/%d: %s — %s", c.CheckID, c.Port, c.State, c.Evidence))
		}
		f := adEvidenceFinding(scope, host, "check-coverage", "Покрытие проверок", strings.Join(lines, "\n"), "Статусы относятся к выполненным проверкам; таймаут и отсутствие прав не означают отсутствие уязвимости.")
		raw, _ := json.Marshal(groups[host])
		f.Response = string(raw)
		findings = append(findings, f)
		for _, c := range groups[host] {
			if c.CheckID == "dns-axfr" && c.State == "confirmed" {
				f := adEvidenceFinding(scope, host, "dns-axfr", "DNS AXFR без авторизации", c.Evidence, "Проверено с адреса сканера; DNS-записи не изменялись.")
				f.Severity = "medium"
				findings = append(findings, f)
			}
		}
	}
	return findings
}
