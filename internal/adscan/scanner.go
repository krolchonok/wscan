// Package adscan provides bounded, unauthenticated discovery of Active
// Directory services on a selected private IPv4 subnet.
package adscan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	probeWorkers   = 64
	probeRate      = 250
	probeTimeout   = 350 * time.Millisecond
	ldapQueryLimit = 3 * time.Second
)

var adPorts = []int{53, 80, 88, 135, 139, 389, 443, 445, 464, 636, 3268, 3269, 3389, 9389}

// Network describes an active interface's private IPv4 subnet.
type Network struct {
	Interface string
	CIDR      string
}

// Controller contains the AD-related ports found at one address and any
// anonymous RootDSE information the directory server allows clients to read.
type Host struct {
	Address                   string
	Ports                     []int
	Roles                     []string
	ADCSPaths                 []ADCSPath
	HostName                  string
	Domain                    string
	LDAPMessage               string
	LDAPUsers                 []string
	ASREPUsers                []string
	SPNUsers                  []string
	PasswordNotRequiredUsers  []string
	PasswordNeverExpiresUsers []string
	DelegationUsers           []string
	ReversibleEncryptionUsers []string
	DESOnlyUsers              []string
	AdminCountUsers           []string
	SMBNull                   bool
	SMBGuest                  bool
	NullShares                []string
	GuestShares               []string
}

// ADCSPath identifies a certificate enrollment endpoint.
type ADCSPath struct {
	Port int
	Path string
}

// Result is the completed subnet discovery summary.
type Result struct {
	CIDR         string
	HostsScanned int
	Hosts        []Host
	DNSRecords   []SRVRecord
}

// SRVRecord is an AD-related DNS service record returned by a discovered DNS server.
type SRVRecord struct {
	Server   string
	Domain   string
	Query    string
	Target   string
	Port     uint16
	Priority uint16
	Weight   uint16
}

// LocalNetworks returns active interfaces on private IPv4 ranges.
func LocalNetworks() ([]Network, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("read network interfaces: %w", err)
	}
	var networks []Network
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ipNet, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || !ip.IsPrivate() {
				continue
			}
			networks = append(networks, Network{
				Interface: iface.Name,
				CIDR:      (&net.IPNet{IP: ip.Mask(ipNet.Mask), Mask: ipNet.Mask}).String(),
			})
		}
	}
	sort.Slice(networks, func(i, j int) bool {
		if networks[i].Interface == networks[j].Interface {
			return networks[i].CIDR < networks[j].CIDR
		}
		return networks[i].Interface < networks[j].Interface
	})
	return networks, nil
}

// ValidatePrivateSubnet accepts an explicitly selected private IPv4 CIDR,
// including routed assessment ranges reached through a VPN.
func ValidatePrivateSubnet(cidr string) (Network, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil || network.IP.To4() == nil {
		return Network{}, fmt.Errorf("укажи IPv4-подсеть в формате CIDR, например 192.168.1.0/24")
	}
	if !network.IP.IsPrivate() {
		return Network{}, fmt.Errorf("подсеть %s не относится к частным IPv4-диапазонам", network.String())
	}
	return Network{Interface: "ручной ввод", CIDR: network.String()}, nil
}

type probe struct {
	address string
	port    int
}

type openPort struct {
	address string
	port    int
}

// Scan probes only the AD-related TCP ports listed in adPorts. It streams
// addresses from the selected private IPv4 subnet, so memory use does not grow
// with subnet size. It never authenticates or performs writes.
func Scan(ctx context.Context, cidr string, progress func(done, total int)) (Result, error) {
	validated, err := ValidatePrivateSubnet(cidr)
	if err != nil {
		return Result{}, err
	}
	_, network, _ := net.ParseCIDR(validated.CIDR)
	prefix, _ := network.Mask.Size()
	firstHost := append(net.IP(nil), network.IP.To4().Mask(network.Mask)...)
	hostCount := uint64(1) << uint(32-prefix)
	if prefix <= 30 {
		incrementIPv4(firstHost)
		hostCount -= 2 // skip the network and broadcast addresses
	}
	totalProbes := int(hostCount) * len(adPorts)

	probes := make(chan probe)
	openPorts := make(chan openPort, probeWorkers)
	var wg sync.WaitGroup
	var completed atomic.Int64
	limiter := time.NewTicker(time.Second / probeRate)
	defer limiter.Stop()
	for i := 0; i < probeWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := net.Dialer{Timeout: probeTimeout}
			for item := range probes {
				select {
				case <-ctx.Done():
					return
				case <-limiter.C:
				}
				address := net.JoinHostPort(item.address, fmt.Sprint(item.port))
				conn, dialErr := dialer.DialContext(ctx, "tcp", address)
				if dialErr == nil {
					_ = conn.Close()
					select {
					case openPorts <- openPort{address: item.address, port: item.port}:
					case <-ctx.Done():
						return
					}
				}
				done := int(completed.Add(1))
				progressEvery := max(128, totalProbes/200)
				if progress != nil && (done%progressEvery == 0 || done == totalProbes) {
					progress(done, totalProbes)
				}
			}
		}()
	}
	go func() {
		defer close(probes)
		address := append(net.IP(nil), firstHost...)
		for host := uint64(0); host < hostCount; host++ {
			addressText := address.String()
			for _, port := range adPorts {
				select {
				case probes <- probe{address: addressText, port: port}:
				case <-ctx.Done():
					return
				}
			}
			incrementIPv4(address)
		}
	}()
	go func() {
		wg.Wait()
		close(openPorts)
	}()

	byAddress := make(map[string][]int)
	for item := range openPorts {
		byAddress[item.address] = append(byAddress[item.address], item.port)
	}
	if err := ctx.Err(); err != nil {
		return Result{CIDR: cidr, HostsScanned: int(completed.Load()) / len(adPorts)}, err
	}

	addresses := make([]string, 0, len(byAddress))
	for address := range byAddress {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return compareIP(addresses[i], addresses[j]) })
	controllers := make([]Host, len(addresses))
	sem := make(chan struct{}, 8)
	var infoWG sync.WaitGroup
	for i, address := range addresses {
		sort.Ints(byAddress[address])
		controllers[i] = Host{Address: address, Ports: byAddress[address]}
		controllers[i].Roles = classifyRoles(controllers[i])
		ports := controllers[i].Ports
		needsLDAP := ldapPort(ports) != 0
		needsADCS := contains(ports, 80) || contains(ports, 443)
		if !needsLDAP && !needsADCS {
			continue
		}
		infoWG.Add(1)
		go func(index int, address string, ports []int) {
			defer infoWG.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if port := ldapPort(ports); port != 0 {
				info := rootDSE(ctx, address, port)
				controllers[index].HostName = info.HostName
				controllers[index].Domain = info.Domain
				controllers[index].LDAPMessage = info.Message
				controllers[index].LDAPUsers = info.Users
				controllers[index].ASREPUsers = info.ASREPUsers
				controllers[index].SPNUsers = info.SPNUsers
				controllers[index].PasswordNotRequiredUsers = info.PasswordNotRequiredUsers
				controllers[index].PasswordNeverExpiresUsers = info.PasswordNeverExpiresUsers
				controllers[index].DelegationUsers = info.DelegationUsers
				controllers[index].ReversibleEncryptionUsers = info.ReversibleEncryptionUsers
				controllers[index].DESOnlyUsers = info.DESOnlyUsers
				controllers[index].AdminCountUsers = info.AdminCountUsers
			}
			for _, port := range ports {
				if port == 80 || port == 443 {
					controllers[index].ADCSPaths = append(controllers[index].ADCSPaths, probeADCS(ctx, address, port)...)
				}
			}
			controllers[index].Roles = classifyRoles(controllers[index])
		}(i, address, append([]int(nil), byAddress[address]...))
	}
	infoWG.Wait()
	if err := ctx.Err(); err != nil {
		return Result{CIDR: cidr, HostsScanned: int(hostCount)}, err
	}
	return Result{CIDR: cidr, HostsScanned: int(hostCount), Hosts: controllers}, nil
}

func classifyRoles(host Host) []string {
	var roles []string
	if host.Domain != "" || host.HostName != "" || (contains(host.Ports, 88) && (contains(host.Ports, 389) || contains(host.Ports, 636))) {
		roles = append(roles, "Контроллер домена")
	}
	if contains(host.Ports, 3268) || contains(host.Ports, 3269) {
		roles = append(roles, "Global Catalog")
	}
	if contains(host.Ports, 389) || contains(host.Ports, 636) {
		if !rolePresent(roles, "Контроллер домена") {
			roles = append(roles, "LDAP")
		}
	}
	if contains(host.Ports, 53) {
		roles = append(roles, "DNS")
	}
	if contains(host.Ports, 9389) {
		roles = append(roles, "AD Web Services")
	}
	if len(host.ADCSPaths) > 0 {
		roles = append(roles, "AD CS")
	}
	if len(roles) == 0 && (contains(host.Ports, 135) || contains(host.Ports, 139) || contains(host.Ports, 445) || contains(host.Ports, 3389)) {
		roles = append(roles, "Windows-узел")
	}
	return roles
}

func rolePresent(roles []string, role string) bool {
	for _, existing := range roles {
		if existing == role {
			return true
		}
	}
	return false
}

func probeADCS(ctx context.Context, address string, port int) []ADCSPath {
	scheme := "http"
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if port == 443 {
		scheme = "https"
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // AD CS commonly uses an internal CA certificate.
	}
	client := &http.Client{Timeout: 1500 * time.Millisecond, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	paths := []string{"/certsrv/", "/CES/", "/ADPolicyProvider_CEP_Kerberos/service.svc"}
	found := make([]ADCSPath, 0, len(paths))
	for _, path := range paths {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(address, fmt.Sprint(port)), path), nil)
		if err != nil {
			continue
		}
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 16*1024))
		_ = response.Body.Close()
		statusSuggestsEndpoint := response.StatusCode == http.StatusOK || response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden
		content := strings.ToLower(string(body))
		signature := strings.Contains(content, "certificate services") || strings.Contains(content, "certification authority") || strings.Contains(content, "enrollment policy") || strings.Contains(content, "enrollment web service") || strings.Contains(content, "certsrv")
		iisProtectedEndpoint := statusSuggestsEndpoint && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) && strings.Contains(strings.ToLower(response.Header.Get("Server")), "iis")
		if statusSuggestsEndpoint && (signature || iisProtectedEndpoint) {
			found = append(found, ADCSPath{Port: port, Path: path})
		}
	}
	return found
}

// EstimateDuration returns the nominal duration at the scanner's fixed probe
// rate. It is informational; timeouts and LDAP follow-up can increase it.
func EstimateDuration(cidr string) time.Duration {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil || network.IP.To4() == nil {
		return 0
	}
	prefix, _ := network.Mask.Size()
	hosts := uint64(1) << uint(32-prefix)
	if prefix <= 30 {
		hosts -= 2
	}
	probes := hosts * uint64(len(adPorts))
	seconds := (probes + probeRate - 1) / probeRate
	return time.Duration(seconds) * time.Second
}

// LookupADSRV queries only DNS servers discovered in the scanned subnet. It
// gathers common LDAP, Kerberos, password-change, and Global Catalog SRV records.
func LookupADSRV(ctx context.Context, hosts []Host) ([]SRVRecord, []string, error) {
	servers := make([]string, 0)
	serverSeen := map[string]bool{}
	domains := make([]string, 0)
	domainSeen := map[string]bool{}
	for _, host := range hosts {
		if contains(host.Ports, 53) && !serverSeen[host.Address] {
			serverSeen[host.Address] = true
			servers = append(servers, host.Address)
		}
		if domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host.Domain)), "."); domain != "" && !domainSeen[domain] {
			domainSeen[domain] = true
			domains = append(domains, domain)
		}
	}
	if len(servers) == 0 || len(domains) == 0 {
		return nil, nil, nil
	}
	sort.Strings(servers)
	sort.Strings(domains)
	servers = servers[:min(len(servers), 4)]
	domains = domains[:min(len(domains), 4)]
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
	workers := min(8, len(servers)*len(domains)*len(queries))
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				serverAddr := net.JoinHostPort(item.server, "53")
				resolver := &net.Resolver{PreferGo: true, Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
					if network != "tcp" {
						network = "udp"
					}
					return (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(dialCtx, network, serverAddr)
				}}
				queryName := item.query.name + item.domain
				queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				_, answers, err := resolver.LookupSRV(queryCtx, item.query.service, item.query.proto, queryName)
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
				for _, answer := range answers[:min(len(answers), 64)] {
					records = append(records, SRVRecord{
						Server: item.server, Domain: item.domain, Query: qname,
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
				select {
				case <-ctx.Done():
					break feed
				case jobs <- job{server: server, domain: domain, query: query}:
				}
			}
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, failures, err
	}
	seen := map[string]bool{}
	unique := records[:0]
	for _, record := range records {
		key := fmt.Sprintf("%s|%s|%s|%s|%d|%d|%d", record.Server, record.Domain, record.Query, record.Target, record.Port, record.Priority, record.Weight)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, record)
		}
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Server != unique[j].Server {
			return unique[i].Server < unique[j].Server
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
		return unique[i].Port < unique[j].Port
	})
	return unique, failures, nil
}

func incrementIPv4(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

type rootDSEInfo struct {
	HostName                  string
	Domain                    string
	Message                   string
	Users                     []string
	ASREPUsers                []string
	SPNUsers                  []string
	PasswordNotRequiredUsers  []string
	PasswordNeverExpiresUsers []string
	DelegationUsers           []string
	ReversibleEncryptionUsers []string
	DESOnlyUsers              []string
	AdminCountUsers           []string
}

const maxAnonymousUsers = 1000

func rootDSE(ctx context.Context, address string, port int) rootDSEInfo {
	return rootDSEAt(ctx, address, port, port == 636 || port == 3269)
}

func rootDSEAt(ctx context.Context, address string, port int, secure bool) rootDSEInfo {
	var info rootDSEInfo
	queryCtx, cancel := context.WithTimeout(ctx, ldapQueryLimit)
	defer cancel()
	scheme := "ldap"
	if secure {
		scheme = "ldaps"
	}
	server := url.URL{Scheme: scheme, Host: net.JoinHostPort(address, fmt.Sprint(port))}
	dialer := &net.Dialer{Timeout: ldapQueryLimit}
	// Reconnaissance must work with private/self-signed directory certificates;
	// this unauthenticated probe never sends user credentials.
	conn, err := ldap.DialURL(server.String(), ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		info.Message = "RootDSE: соединение не установлено: " + err.Error()
		return info
	}
	defer conn.Close()
	stop := context.AfterFunc(queryCtx, func() { _ = conn.Close() })
	defer stop()
	conn.SetTimeout(ldapQueryLimit)
	if deadline, ok := queryCtx.Deadline(); ok {
		conn.SetTimeout(time.Until(deadline))
	}
	request := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, int(ldapQueryLimit.Seconds()), false,
		"(objectClass=*)", []string{"defaultNamingContext", "rootDomainNamingContext", "dnsHostName"}, nil)
	response, err := conn.Search(request)
	if err != nil {
		info.Message = "RootDSE: запрос завершился ошибкой: " + err.Error()
		return info
	}
	if response == nil || len(response.Entries) == 0 {
		info.Message = "RootDSE: сервер не вернул данных"
		return info
	}
	entry := response.Entries[0]
	info.HostName = entry.GetAttributeValue("dnsHostName")
	dn := entry.GetAttributeValue("defaultNamingContext")
	if dn == "" {
		dn = entry.GetAttributeValue("rootDomainNamingContext")
	}
	info.Domain = domainFromDN(dn)
	if info.Domain == "" {
		info.Message = "LDAP открыт; домен не раскрыт"
	} else {
		info.Message = "RootDSE прочитан анонимно"
		info.Users, info.ASREPUsers, info.SPNUsers,
			info.PasswordNotRequiredUsers, info.PasswordNeverExpiresUsers,
			info.DelegationUsers, info.ReversibleEncryptionUsers,
			info.DESOnlyUsers, info.AdminCountUsers, info.Message = anonymousLDAPUsers(conn, dn)
		info.Message = "RootDSE прочитан анонимно; " + info.Message
	}
	return info
}

func anonymousLDAPUsers(conn *ldap.Conn, baseDN string) (users, asrepUsers, spnUsers, passwordNotRequired, passwordNeverExpires, delegation, reversibleEncryption, desOnly, adminCount []string, message string) {
	request := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, maxAnonymousUsers, int(ldapQueryLimit.Seconds()), false,
		"(&(objectCategory=person)(objectClass=user)(sAMAccountName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
		[]string{"sAMAccountName", "userAccountControl", "servicePrincipalName", "adminCount"}, nil)
	response, err := conn.Search(request)
	message = "LDAP-пользователи: записей не получено"
	if err != nil {
		message = "LDAP-пользователи: " + err.Error()
	}
	if response == nil || len(response.Entries) == 0 {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, message
	}
	message = fmt.Sprintf("LDAP-пользователи: получено записей %d", len(response.Entries))
	if err != nil {
		message += "; результат неполный: " + err.Error()
	}
	for _, entry := range response.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		if name == "" {
			continue
		}
		users = append(users, name)
		if control, parseErr := strconv.ParseUint(entry.GetAttributeValue("userAccountControl"), 10, 32); parseErr == nil {
			if control&0x00400000 != 0 {
				asrepUsers = append(asrepUsers, name)
			}
			if control&0x00000020 != 0 {
				passwordNotRequired = append(passwordNotRequired, name)
			}
			if control&0x00010000 != 0 {
				passwordNeverExpires = append(passwordNeverExpires, name)
			}
			if control&0x00080000 != 0 && control&0x01000000 == 0 {
				delegation = append(delegation, name)
			}
			if control&0x00000080 != 0 {
				reversibleEncryption = append(reversibleEncryption, name)
			}
			if control&0x00200000 != 0 {
				desOnly = append(desOnly, name)
			}
		}
		if len(entry.GetAttributeValues("servicePrincipalName")) > 0 {
			spnUsers = append(spnUsers, name)
		}
		if entry.GetAttributeValue("adminCount") == "1" {
			adminCount = append(adminCount, name)
		}
	}
	return uniqueSorted(users), uniqueSorted(asrepUsers), uniqueSorted(spnUsers),
		uniqueSorted(passwordNotRequired), uniqueSorted(passwordNeverExpires), uniqueSorted(delegation),
		uniqueSorted(reversibleEncryption), uniqueSorted(desOnly), uniqueSorted(adminCount), message
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func domainFromDN(dn string) string {
	var labels []string
	for _, part := range strings.Split(dn, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(key, "DC") && value != "" {
			labels = append(labels, value)
		}
	}
	return strings.Join(labels, ".")
}

func contains(values []int, value int) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func compareIP(a, b string) bool {
	return bytesCompare(net.ParseIP(a).To4(), net.ParseIP(b).To4()) < 0
}

func bytesCompare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return len(a) - len(b)
}

func ldapPort(ports []int) int {
	for _, port := range []int{389, 3268, 636, 3269} {
		if contains(ports, port) {
			return port
		}
	}
	return 0
}
