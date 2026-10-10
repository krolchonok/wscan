// Package discovery implements host discovery and the built-in TCP connect scanner.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"wscan/internal/domain"
)

type Config struct {
	LibraryDir        string
	OnlyKnownServices bool
	Concurrency       int
	RPS               int
	Timeout           time.Duration
	AllPorts          bool
	// Ports, when non-empty, is the explicit TCP port set to scan (overrides
	// the built-in common list and AllPorts).
	Ports []int
	// UDPPorts, when non-empty, enables a best-effort UDP probe of those ports.
	UDPPorts []int
	// NoVersion skips service/version identification probes.
	NoVersion bool
	// SkipTCP disables the TCP pass entirely (for UDP-only scans).
	SkipTCP bool
	// Progress reports completed probes, including closed or silent ports.
	// Calls are serialized even when probes run concurrently.
	Progress func(target string, done, total int)
	// Internal marker: a recovery pass must not start another recovery pass.
	recoveryPass bool
}

type Scanner struct{ Config Config }

var commonPorts = []int{20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 179, 389, 443, 445, 464, 465, 500, 514, 515, 520, 587, 593, 631, 636, 873, 902, 993, 995, 1025, 1080, 1099, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2181, 2375, 2376, 2483, 2484, 3000, 3128, 3268, 3269, 3306, 3389, 4000, 4443, 5000, 5001, 5432, 5601, 5672, 5722, 5900, 5985, 5986, 6379, 6443, 7001, 7002, 8000, 8008, 8080, 8081, 8088, 8090, 8443, 8888, 9000, 9042, 9090, 9091, 9200, 9300, 9389, 9418, 10000, 11211, 27017}

var serviceNames = map[int]string{20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "smb", 464: "kpasswd", 465: "smtps", 587: "submission", 593: "rpc-http", 631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3128: "http-proxy", 3268: "ldap-gc", 3269: "ldaps-gc", 3306: "mysql", 3389: "rdp", 4443: "https-alt", 5000: "http-alt", 5001: "https-alt", 5432: "postgresql", 5601: "http-alt", 5672: "amqp", 5722: "msdfsr", 5900: "vnc", 5985: "winrm", 5986: "winrm-https", 6379: "redis", 6443: "https-alt", 7001: "weblogic", 7002: "https-alt", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8088: "http-alt", 8090: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9042: "cassandra", 9090: "http-alt", 9200: "elasticsearch", 9300: "elasticsearch", 9389: "adws", 9418: "git", 10000: "http-alt", 11211: "memcached", 27017: "mongodb"}

func (s Scanner) Scan(ctx context.Context, target string) ([]domain.Service, error) {
	c := s.Config
	database := loadServices(c.LibraryDir)
	if c.Concurrency < 1 {
		c.Concurrency = 256
	}
	if c.Concurrency > 2048 {
		c.Concurrency = 2048
	}
	if c.RPS < 0 {
		c.RPS = 1000
	}
	if c.Timeout <= 0 {
		c.Timeout = 450 * time.Millisecond
	}
	host := target
	if !IsNetworkTarget(target) {
		var err error
		host, err = TargetHost(target)
		if err != nil {
			return nil, err
		}
	}
	ips, err := ResolveTargetIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	ports := commonPorts
	switch {
	case len(c.Ports) > 0:
		ports = c.Ports
	case c.AllPorts:
		ports = make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
	}
	interval := time.Duration(0)
	if c.RPS > 0 {
		interval = max(time.Nanosecond, time.Second/time.Duration(c.RPS))
	}
	tcpCount := len(ports)
	if c.SkipTCP {
		tcpCount = 0
	}
	total := len(ips) * (tcpCount + len(c.UDPPorts))
	var progressMu sync.Mutex
	completed := 0
	if c.Progress != nil {
		c.Progress(target, 0, total)
	}
	complete := func() {
		if c.Progress == nil || ctx.Err() != nil {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()
		completed++
		if completed%max(1, total/100) == 0 || completed == total {
			c.Progress(target, completed, total)
		}
	}
	var rateTick <-chan time.Time
	if interval > 0 {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateTick = ticker.C
	}
	type probe struct {
		ip   net.IP
		port int
	}
	jobs := make(chan probe)
	results := make(chan domain.Service, c.Concurrency)
	var retryMu sync.Mutex
	retryPorts := make(map[string][]int)
	var resetStreak atomic.Int32
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		dialer := net.Dialer{Timeout: c.Timeout}
		for p := range jobs {
			func() {
				defer complete()
				if !waitProbe(ctx, rateTick) {
					return
				}
				// Soft backoff when the host resets connections under load.
				if n := resetStreak.Load(); n >= 4 {
					delay := time.Duration(min(int(n), 25)) * 25 * time.Millisecond
					select {
					case <-ctx.Done():
						return
					case <-time.After(delay):
					}
				}
				address := net.JoinHostPort(p.ip.String(), strconv.Itoa(p.port))
				conn, err := dialer.DialContext(ctx, "tcp", address)
				if err != nil {
					if discoveryOverload(err) {
						resetStreak.Add(1)
					}
					if !c.recoveryPass && ctx.Err() == nil && retryableTCPProbe(err) {
						retryMu.Lock()
						retryPorts[p.ip.String()] = append(retryPorts[p.ip.String()], p.port)
						retryMu.Unlock()
					}
					return
				}
				resetStreak.Store(0)
				name := serviceNames[p.port]
				tunnel := ""
				if p.port == 443 || p.port == 465 || p.port == 636 || p.port == 3269 || p.port == 993 || p.port == 995 || p.port == 5986 || p.port == 8443 {
					tunnel = "ssl"
				}
				service := domain.Service{Host: p.ip.String(), Port: p.port, Protocol: "tcp", Name: name, PortService: database.names["tcp"][p.port], Tunnel: tunnel, State: "open"}
				if !c.NoVersion {
					service = identifyService(ctx, conn, service, c.Timeout)
				}
				_ = conn.Close()
				if c.OnlyKnownServices && !knownService(service.Name) {
					return
				}
				results <- service
			}()
		}
	}
	for i := 0; i < c.Concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	go func() {
		defer close(jobs)
		if c.SkipTCP {
			return
		}
		for _, ip := range ips {
			for _, port := range ports {
				select {
				case jobs <- probe{ip: ip.IP, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	var open []domain.Service
	for item := range results {
		open = append(open, item)
	}
	if err := ctx.Err(); err != nil {
		return open, err
	}
	if !c.recoveryPass && len(retryPorts) > 0 {
		// A silent port is not proven closed. Retry the requested uncertain
		// ports with less pressure, including ports absent from commonPorts.
		for _, pending := range retryPorts {
			total += len(pending)
		}
		if c.Progress != nil {
			c.Progress(target, completed, total)
		}
		open = append(open, s.recheckUncertain(ctx, ips, retryPorts, c, complete)...)
	}
	// Full-range floods often make small devices (routers, IoT) drop SYNs on
	// common ports like 80/443 while a random high port still "wins". After a
	// large sweep, gently re-check the common list for anything missed.
	if !c.SkipTCP && !c.recoveryPass && (c.AllPorts || len(ports) > 5000) {
		open = append(open, s.recheckCommon(ctx, ips, open, c)...)
	}
	if len(c.UDPPorts) > 0 {
		open = append(open, s.scanUDP(ctx, ips, c, complete, rateTick)...)
	}
	if err := ctx.Err(); err != nil {
		return open, err
	}
	return open, nil
}

func retryableTCPProbe(err error) bool {
	if err == nil || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, context.Canceled) {
		return false
	}
	var networkError net.Error
	return (errors.As(err, &networkError) && networkError.Timeout()) ||
		discoveryOverload(err) || errors.Is(err, syscall.EADDRNOTAVAIL)
}

func (s Scanner) recheckUncertain(ctx context.Context, ips []net.IPAddr, pending map[string][]int, c Config, complete func()) []domain.Service {
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(400 * time.Millisecond):
	}
	var extra []domain.Service
	for _, ip := range ips {
		ports := pending[ip.IP.String()]
		if len(ports) == 0 || ctx.Err() != nil {
			continue
		}
		sort.Ints(ports)
		rps := 500
		if c.RPS > 0 {
			rps = min(rps, c.RPS)
		}
		child := Scanner{Config: Config{
			LibraryDir: c.LibraryDir, Ports: ports,
			Concurrency: min(c.Concurrency, 32), RPS: rps,
			Timeout:           max(c.Timeout, 1500*time.Millisecond),
			OnlyKnownServices: c.OnlyKnownServices, NoVersion: c.NoVersion,
			recoveryPass: true,
		}}
		if c.Progress != nil {
			previous := 0
			child.Config.Progress = func(_ string, done, _ int) {
				for previous < done {
					complete()
					previous++
				}
			}
		}
		services, _ := child.Scan(ctx, ip.IP.String())
		extra = append(extra, services...)
	}
	return extra
}

// recheckCommon re-probes commonPorts that were not found open, with low
// concurrency and a floor timeout. Used after large/all-ports sweeps.
func (s Scanner) recheckCommon(ctx context.Context, ips []net.IPAddr, already []domain.Service, c Config) []domain.Service {
	found := make(map[string]bool, len(already))
	for _, svc := range already {
		found[net.JoinHostPort(svc.Host, strconv.Itoa(svc.Port))] = true
	}
	timeout := c.Timeout
	if timeout < time.Second {
		timeout = time.Second
	}
	var extra []domain.Service
	requested := make(map[int]bool, len(c.Ports))
	for _, port := range c.Ports {
		requested[port] = true
	}
	// Two gentle passes with a short cooldown — small devices often need a
	// moment to recover after a full-range flood before 80/443 answer again.
	for pass := 0; pass < 2; pass++ {
		if pass > 0 {
			select {
			case <-ctx.Done():
				return extra
			case <-time.After(400 * time.Millisecond):
			}
		} else {
			select {
			case <-ctx.Done():
				return extra
			case <-time.After(250 * time.Millisecond):
			}
		}
		var missing []int
		for _, port := range commonPorts {
			if len(c.Ports) > 0 && !requested[port] {
				continue
			}
			need := false
			for _, ip := range ips {
				if !found[net.JoinHostPort(ip.IP.String(), strconv.Itoa(port))] {
					need = true
					break
				}
			}
			if need {
				missing = append(missing, port)
			}
		}
		if len(missing) == 0 {
			break
		}
		child := Scanner{Config: Config{
			LibraryDir:        c.LibraryDir,
			Ports:             missing,
			Concurrency:       32,
			Timeout:           timeout,
			OnlyKnownServices: c.OnlyKnownServices,
			NoVersion:         c.NoVersion,
			recoveryPass:      true,
		}}
		for _, ip := range ips {
			if ctx.Err() != nil {
				return extra
			}
			svcs, err := child.Scan(ctx, ip.IP.String())
			if err != nil {
				continue
			}
			for _, svc := range svcs {
				key := net.JoinHostPort(svc.Host, strconv.Itoa(svc.Port))
				if found[key] {
					continue
				}
				found[key] = true
				extra = append(extra, svc)
			}
		}
	}
	return extra
}

// udpProbes carries small protocol-specific payloads that elicit a reply from
// common UDP services; unlisted ports get a single null byte.
var udpProbes = map[int][]byte{
	1434: {0x02},
	53:   {0x00, 0x1e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00, 0x00, 0x10, 0x00, 0x03},
	123:  append([]byte{0x1b}, make([]byte, 47)...),
	161:  {0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xa0, 0x19, 0x02, 0x04, 0x70, 0x69, 0x6e, 0x67, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00},
	1900: []byte("M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n"),
}

// scanUDP performs a best-effort UDP sweep: a port is reported open only when
// it replies to a probe. Silent ports are open|filtered and omitted to avoid
// noise, and ICMP-unreachable (closed) ports surface as a read error. Reliable
// closed/open-filtered discrimination needs raw ICMP (root), which this
// unprivileged scanner does not use.
func (s Scanner) scanUDP(ctx context.Context, ips []net.IPAddr, c Config, complete func(), rateTick <-chan time.Time) []domain.Service {
	database := loadServices(c.LibraryDir)
	workers := c.Concurrency
	if workers > 256 {
		workers = 256
	}
	type probe struct {
		ip   net.IP
		port int
	}
	jobs := make(chan probe)
	results := make(chan domain.Service, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := net.Dialer{Timeout: c.Timeout}
			for p := range jobs {
				func() {
					defer complete()
					if !waitProbe(ctx, rateTick) {
						return
					}
					select {
					case <-ctx.Done():
						return
					default:
					}
					addr := net.JoinHostPort(p.ip.String(), strconv.Itoa(p.port))
					conn, err := dialer.DialContext(ctx, "udp", addr)
					if err != nil {
						return
					}
					payload := udpProbes[p.port]
					if payload == nil {
						payload = []byte{0x00}
					}
					_ = conn.SetDeadline(time.Now().Add(c.Timeout))
					if _, err := conn.Write(payload); err != nil {
						_ = conn.Close()
						return
					}
					buf := make([]byte, 1024)
					n, err := conn.Read(buf)
					_ = conn.Close()
					if err != nil || n == 0 {
						return // timeout (open|filtered) or ICMP unreachable (closed)
					}
					name := udpServiceNames[p.port]
					if p.port == 1434 {
						if n < 4 || buf[0] != 0x05 || !strings.Contains(string(buf[3:n]), "ServerName;") || !strings.Contains(string(buf[3:n]), "InstanceName;") {
							name = ""
						}
					}
					if c.OnlyKnownServices && !knownService(name) {
						return
					}
					results <- domain.Service{Host: p.ip.String(), Port: p.port, Protocol: "udp", Name: name, PortService: database.names["udp"][p.port], State: "open"}
				}()
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range ips {
			for _, port := range c.UDPPorts {
				select {
				case jobs <- probe{ip: ip.IP, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	var out []domain.Service
	for s := range results {
		out = append(out, s)
	}
	return out
}

var udpServiceNames = map[int]string{1434: "mssql-browser", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 161: "snmp", 162: "snmptrap", 500: "isakmp", 514: "syslog", 520: "rip", 1900: "ssdp", 5353: "mdns"}

func TargetHost(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty target")
	}
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", err
		}
		target = u.Host
	}
	target = strings.TrimSuffix(target, ".")
	if h, _, err := net.SplitHostPort(target); err == nil {
		target = h
	} else {
		target = strings.Trim(target, "[]")
	}
	if strings.HasPrefix(target, "-") || strings.ContainsAny(target, "/\\ \t\r\n") {
		return "", fmt.Errorf("target must be a single IP address or domain name")
	}
	if net.ParseIP(target) != nil {
		return target, nil
	}
	if len(target) > 253 {
		return "", fmt.Errorf("domain name is too long")
	}
	for _, label := range strings.Split(target, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid IP/domain target %q", target)
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", fmt.Errorf("invalid IP/domain target %q", target)
			}
		}
	}
	return target, nil
}

func WebURL(service domain.Service) (string, bool) {
	if service.Protocol != "tcp" {
		return "", false
	}
	name := strings.ToLower(service.Name)
	secure := service.Tunnel == "ssl" || service.Tunnel == "tls" || strings.Contains(name, "https") || name == "wsmans" || service.Port == 5986
	if !strings.Contains(name, "http") && !strings.Contains(name, "winrm") && name != "wsman" && name != "wsmans" && service.Port != 5985 && service.Port != 5986 && service.Port != 80 && service.Port != 443 && service.Port != 8000 && service.Port != 8008 && service.Port != 8080 && service.Port != 8081 && service.Port != 8443 {
		return "", false
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(service.Host, strconv.Itoa(service.Port))), true
}

func waitProbe(ctx context.Context, tick <-chan time.Time) bool {
	if ctx.Err() != nil {
		return false
	}
	if tick == nil {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-tick:
		return true
	}
}

func knownService(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name != "" && name != "unknown" && name != "tcp" && name != "udp"
}

// discoveryOverload detects dial failures that look like the host/stack is
// saturated. "connection refused" and plain timeouts are normal closed/filtered
// ports and must not throttle the scan.
func discoveryOverload(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "too many open files") ||
		strings.Contains(s, "no buffer space") ||
		strings.Contains(s, "resource temporarily unavailable")
}
