package adscan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// IdentityFact retains provenance instead of treating a name as proof of a role.
type IdentityFact struct{ Kind, Value, Source string }

func hasADDSCapability(capabilities []string) bool {
	ad, lds := false, false
	for _, value := range capabilities {
		ad = ad || value == "1.2.840.113556.1.4.800"
		lds = lds || value == "1.2.840.113556.1.4.1851"
	}
	return ad && !lds
}

// Discover is the UI-independent unauthenticated AD reconnaissance pipeline.
// DNS endpoints may be supplied for routed networks. SRV targets are inventoried,
// never appended to the scan scope or probed automatically.
func Discover(ctx context.Context, cidr string, options DNSOptions, progress func(string, int, int)) (Result, error) {
	options, err := options.normalized()
	if err != nil {
		return Result{}, err
	}
	emit := func(stage string, done, total int) {
		if progress != nil {
			progress(stage, done, total)
		}
	}
	emit("Обнаружение AD/Windows-портов", 0, 0)
	result, err := Scan(ctx, cidr, func(done, total int) { emit("Обнаружение AD/Windows-портов", done, total) })
	if err != nil {
		return result, err
	}
	emit("Топология AD: DNS SRV", 0, 0)
	result.DNSRecords, result.Diagnostics, err = LookupADSRVWithOptions(ctx, result.Hosts, options)
	if err != nil {
		return result, err
	}
	emit("Связываю DNS-имена с найденными узлами", 0, 0)
	err = enrichDNSIdentity(ctx, &result)
	return result, err
}

// enrichDNSIdentity connects SRV observations to existing IPs, without expanding
// the selected CIDR. DNS advertisement does not prove the service is a live DC.
func enrichDNSIdentity(ctx context.Context, result *Result) error {
	byIP := map[string]int{}
	byName := map[string][]int{}
	for i, host := range result.Hosts {
		byIP[host.Address] = i
		if host.HostName != "" {
			name := strings.ToLower(strings.TrimSuffix(host.HostName, "."))
			byName[name] = append(byName[name], i)
		}
	}
	type resolution struct {
		ips []net.IPAddr
		err error
	}
	cache := map[string]resolution{}
	for _, record := range result.DNSRecords {
		if err := ctx.Err(); err != nil {
			return err
		}
		port := record.ServerPort
		if port == 0 {
			port = 53
		}
		server := net.JoinHostPort(record.Server, fmt.Sprint(port))
		key := server + "|" + record.Target
		resolved, ok := cache[key]
		if !ok {
			if len(cache) >= 256 {
				result.Diagnostics = append(result.Diagnostics, "DNS-идентификация неполная: достигнут лимит 256 имён; все SRV-записи сохранены.")
				break
			}
			resolver := dnsResolver(server)
			queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			resolved.ips, resolved.err = resolver.LookupIPAddr(queryCtx, strings.TrimSuffix(record.Target, ".")+".")
			cancel()
			cache[key] = resolved
			if resolved.err != nil {
				result.Diagnostics = append(result.Diagnostics, "DNS-имя "+record.Target+": "+resolved.err.Error())
			}
		}
		indexes := map[int]bool{}
		for _, ip := range resolved.ips {
			if i, ok := byIP[ip.IP.String()]; ok {
				indexes[i] = true
			}
		}
		for _, i := range byName[strings.ToLower(record.Target)] {
			indexes[i] = true
		}
		for i := range indexes {
			host := &result.Hosts[i]
			source := "DNS " + server + " " + record.Query
			appendIdentity(host, IdentityFact{Kind: "hostname", Value: record.Target, Source: source})
			appendIdentity(host, IdentityFact{Kind: "domain", Value: record.Domain, Source: source})
			if host.HostName == "" {
				host.HostName = record.Target
			}
			if host.Domain == "" {
				host.Domain = record.Domain
			}
			if strings.HasPrefix(record.Query, "_ldap._tcp.dc._msdcs.") {
				host.DCDNSAdvertised = true
				appendIdentity(host, IdentityFact{Kind: "role", Value: "Предполагаемый контроллер домена", Source: source})
			}
			host.Roles = classifyRoles(*host)
		}
	}
	return ctx.Err()
}

func appendIdentity(host *Host, fact IdentityFact) {
	for _, old := range host.Identity {
		if old == fact {
			return
		}
	}
	host.Identity = append(host.Identity, fact)
}
