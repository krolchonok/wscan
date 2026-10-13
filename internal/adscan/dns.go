package adscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func LookupADSRV(ctx context.Context, hosts []Host) ([]SRVRecord, []string, error) {
	return LookupADSRVWithOptions(ctx, hosts, DNSOptions{})
}

func LookupADSRVWithOptions(ctx context.Context, hosts []Host, options DNSOptions) ([]SRVRecord, []string, error) {
	options, err := options.normalized()
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	servers := append([]string(nil), options.Servers...)
	serverSeen := map[string]bool{}
	for _, server := range servers {
		serverSeen[server] = true
	}
	domains := append([]string(nil), options.Domains...)
	domainSeen := map[string]bool{}
	for _, domain := range domains {
		domainSeen[domain] = true
	}
	for _, host := range hosts {
		server := net.JoinHostPort(host.Address, "53")
		if contains(host.Ports, 53) && !serverSeen[server] {
			serverSeen[server] = true
			servers = append(servers, server)
		}
		if domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host.Domain)), "."); domain != "" && !domainSeen[domain] {
			domainSeen[domain] = true
			domains = append(domains, domain)
		}
	}
	if len(servers) == 0 {
		return nil, []string{"DNS SRV пропущен: DNS-сервер не найден; укажите DNS вручную."}, nil
	}
	if len(domains) == 0 {
		return nil, []string{"DNS SRV пропущен: домен не раскрыт; укажите DNS-имя домена вручную."}, nil
	}
	sort.Strings(servers)
	sort.Strings(domains)
	queries := []struct {
		service, proto, name string
	}{
		{"ldap", "tcp", "dc._msdcs."},
		{"ldap", "tcp", ""},
		{"kerberos", "tcp", ""},
		{"kerberos", "udp", ""},
		{"kpasswd", "tcp", ""},
		{"gc", "tcp", ""},
	}
	type job struct {
		server, domain string
		query          struct{ service, proto, name string }
	}
	jobs := make(chan job)
	var mu sync.Mutex
	var records []SRVRecord
	var failures []string
	var wg sync.WaitGroup
	workers := min(8, options.MaxQueries)
	issued := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				serverAddr := item.server
				resolver := dnsResolver(serverAddr)
				queryName := item.query.name + item.domain
				queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				_, answers, err := resolver.LookupSRV(queryCtx, item.query.service, item.query.proto, queryName+".")
				cancel()
				mu.Lock()
				if err != nil {
					var dnsErr *net.DNSError
					if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
						failures = append(failures, serverAddr+" "+queryName+": "+err.Error())
					}
					mu.Unlock()
					continue
				}
				qname := "_" + item.query.service + "._" + item.query.proto + "." + queryName
				if len(answers) > options.MaxAnswers {
					failures = append(failures, qname+": результат неполный; достигнут лимит SRV-ответов")
				}
				for _, answer := range answers[:min(len(answers), options.MaxAnswers)] {
					if answer.Target == "." {
						continue
					}
					serverIP, serverPort, _ := net.SplitHostPort(item.server)
					portNumber, _ := strconv.Atoi(serverPort)
					records = append(records, SRVRecord{
						Server: serverIP, ServerPort: uint16(portNumber), Domain: item.domain, Query: qname,
						Target: strings.TrimSuffix(strings.ToLower(answer.Target), "."),
						Port:   answer.Port, Priority: answer.Priority, Weight: answer.Weight,
					})
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, server := range servers {
		for _, domain := range domains {
			for _, query := range queries {
				if issued >= options.MaxQueries {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("DNS SRV: покрытие неполное; достигнут лимит %d запросов", options.MaxQueries))
					mu.Unlock()
					break feed
				}
				select {
				case <-ctx.Done():
					break feed
				case jobs <- job{server: server, domain: domain, query: query}:
					issued++
				}
			}
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, failures, err
	}
	// Resolver/socket deadlines can fire before the parent's cancellation
	// callback runs. An expired parent deadline must not become nil success.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return nil, failures, context.DeadlineExceeded
	}
	seen := map[string]bool{}
	unique := records[:0]
	for _, record := range records {
		key := fmt.Sprintf("%s|%d|%s|%s|%s|%d|%d|%d", record.Server, record.ServerPort, record.Domain, record.Query, record.Target, record.Port, record.Priority, record.Weight)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, record)
		}
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Server != unique[j].Server {
			return unique[i].Server < unique[j].Server
		}
		if unique[i].ServerPort != unique[j].ServerPort {
			return unique[i].ServerPort < unique[j].ServerPort
		}
		if unique[i].Query != unique[j].Query {
			return unique[i].Query < unique[j].Query
		}
		if unique[i].Priority != unique[j].Priority {
			return unique[i].Priority < unique[j].Priority
		}
		if unique[i].Target != unique[j].Target {
			return unique[i].Target < unique[j].Target
		}
		if unique[i].Port != unique[j].Port {
			return unique[i].Port < unique[j].Port
		}
		return unique[i].Weight < unique[j].Weight
	})
	sort.Strings(failures)
	return unique, failures, nil
}

// DNSOptions supplements discovered servers/domains. Zero limits select defaults;
// reaching a limit always reports incomplete coverage instead of silently truncating.
type DNSOptions struct {
	Servers    []string
	Domains    []string
	MaxQueries int
	MaxAnswers int
}

func ValidateDNSOptions(options DNSOptions) (DNSOptions, error) { return options.normalized() }

func (options DNSOptions) normalized() (DNSOptions, error) {
	if options.MaxQueries == 0 {
		options.MaxQueries = 1024
	}
	if options.MaxAnswers == 0 {
		options.MaxAnswers = 64
	}
	if options.MaxQueries < 1 || options.MaxQueries > 100000 || options.MaxAnswers < 1 || options.MaxAnswers > 4096 {
		return options, fmt.Errorf("DNS: лимит запросов 1–100000, ответов 1–4096")
	}
	var servers, domains []string
	for _, raw := range options.Servers {
		raw = strings.TrimSpace(raw)
		ip, port := raw, "53"
		if net.ParseIP(raw) == nil {
			var err error
			ip, port, err = net.SplitHostPort(raw)
			if err != nil {
				return options, fmt.Errorf("DNS-сервер: укажите IP или IP:порт: %q", raw)
			}
		}
		n, err := strconv.Atoi(port)
		if net.ParseIP(ip) == nil || err != nil || n < 1 || n > 65535 {
			return options, fmt.Errorf("некорректный DNS-сервер: %q", raw)
		}
		servers = append(servers, net.JoinHostPort(net.ParseIP(ip).String(), strconv.Itoa(n)))
	}
	for _, raw := range options.Domains {
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if len(domain) == 0 || len(domain) > 253 {
			return options, fmt.Errorf("некорректное DNS-имя домена: %q", raw)
		}
		for _, label := range strings.Split(domain, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return options, fmt.Errorf("некорректное DNS-имя домена: %q", raw)
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return options, fmt.Errorf("некорректное DNS-имя домена: %q", raw)
				}
			}
		}
		domains = append(domains, domain)
	}
	options.Servers, options.Domains = uniqueSorted(servers), uniqueSorted(domains)
	return options, nil
}

func dnsResolver(server string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" {
			network = "udp"
		}
		return (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, network, server)
	}}
}
