package discovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var pingSequence atomic.Uint32

// IsNetworkTarget reports whether target is an IP network rather than a host.
func IsNetworkTarget(target string) bool {
	_, _, err := net.ParseCIDR(target)
	return err == nil
}

// ValidateTarget accepts the host/URL syntax supported by TargetHost plus
// IPv4/IPv6 CIDRs.
func ValidateTarget(target string) error {
	if _, _, err := net.ParseCIDR(target); err == nil {
		return nil
	}
	_, err := TargetHost(target)
	return err
}

// ExpandCIDR returns usable addresses from a CIDR. IPv4 network and broadcast
// addresses are omitted except for /31 and /32, where both/all addresses are
// valid endpoints.
func ExpandCIDR(cidr string) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid network %q: %w", cidr, err)
	}
	if ip.To4() != nil {
		ip = ip.To4()
	}
	first := append(net.IP(nil), network.IP...)
	ipv4 := ip.To4() != nil
	prefix := bitsOnes(network.Mask)
	if ipv4 && prefix <= 30 {
		incrementIP(first)
	}
	broadcast := append(net.IP(nil), network.IP...)
	if ipv4 && prefix <= 30 {
		for i := range broadcast {
			broadcast[i] |= ^network.Mask[i]
		}
	}
	var out []string
	for current := append(net.IP(nil), first...); network.Contains(current); incrementIP(current) {
		if ipv4 && prefix <= 30 && current.Equal(broadcast) {
			break
		}
		out = append(out, current.String())
	}
	return out, nil
}

func bitsOnes(mask net.IPMask) int { n, _ := mask.Size(); return n }

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

// ResolveTargetIPs expands a CIDR or resolves a host to IP addresses.
func ResolveTargetIPs(ctx context.Context, target string) ([]net.IPAddr, error) {
	if IsNetworkTarget(target) {
		addresses, err := ExpandCIDR(target)
		if err != nil {
			return nil, err
		}
		out := make([]net.IPAddr, 0, len(addresses))
		for _, address := range addresses {
			out = append(out, net.IPAddr{IP: net.ParseIP(address)})
		}
		return out, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", target, err)
	}
	return ips, nil
}

// LiveHosts tries ICMP echo, TCP-connect probes (including connection refused),
// and, on Linux, confirmed neighbors learned by the kernel during those probes.
// Filtered hosts may remain undiscovered; no response does not prove a host offline.
func LiveHosts(ctx context.Context, targets []string, concurrency, rps int, timeout time.Duration, progress func(done, total int)) ([]string, error) {
	if concurrency < 1 {
		concurrency = 128
	}
	if concurrency > 1024 {
		concurrency = 1024
	}
	if timeout <= 0 {
		timeout = 700 * time.Millisecond
	}
	if rps < 0 {
		rps = 500
	}
	var hosts []string
	for _, target := range targets {
		ips, err := ResolveTargetIPs(ctx, target)
		if err != nil {
			return hosts, err
		}
		for _, ip := range ips {
			hosts = append(hosts, ip.IP.String())
		}
	}
	hosts = uniqueSorted(hosts)
	candidates := hosts
	ports := []int{445, 135, 139, 389, 636, 3268, 3269, 88, 464, 53, 3389, 5985, 5986, 9389, 80, 443}
	type probe struct {
		host string
		port int
	}
	jobs := make(chan probe)
	var wg sync.WaitGroup
	var done atomic.Int64
	var mu sync.Mutex
	live := map[string]bool{}
	pings := make(map[string]*sync.Once, len(candidates))
	for _, host := range candidates {
		pings[host] = &sync.Once{}
	}
	var tick <-chan time.Time
	var ticker *time.Ticker
	if rps > 0 {
		ticker = time.NewTicker(max(time.Nanosecond, time.Second/time.Duration(rps)))
		tick = ticker.C
		defer ticker.Stop()
	}
	total := len(hosts)*len(ports) + 1 // Reserve the final step for neighbor confirmation.
	if progress != nil {
		progress(0, total)
	}
	worker := func() {
		defer wg.Done()
		dialer := net.Dialer{Timeout: timeout}
		for p := range jobs {
			mu.Lock()
			alreadyLive := live[p.host]
			mu.Unlock()
			if alreadyLive {
				n := int(done.Add(1))
				if progress != nil && (n%max(1, len(candidates)*len(ports)/100) == 0 || n == len(candidates)*len(ports)) {
					progress(n, total)
				}
				continue
			}
			if tick != nil {
				select {
				case <-ctx.Done():
					return
				case <-tick:
				}
			} else if ctx.Err() != nil {
				return
			}
			// Try ICMP once per address before TCP-connect fallback probes.
			// Fall back to raw ICMP or the system ping executable when
			// unprivileged ping sockets are unavailable.
			pings[p.host].Do(func() {
				if pingHost(ctx, p.host, timeout) {
					mu.Lock()
					live[p.host] = true
					mu.Unlock()
				}
			})
			mu.Lock()
			aliveAfterPing := live[p.host]
			mu.Unlock()
			if aliveAfterPing {
				n := int(done.Add(1))
				if progress != nil && (n%max(1, len(candidates)*len(ports)/100) == 0 || n == len(candidates)*len(ports)) {
					progress(n, total)
				}
				continue
			}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(p.host, fmt.Sprint(p.port)))
			if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
				if conn != nil {
					_ = conn.Close()
				}
				mu.Lock()
				live[p.host] = true
				mu.Unlock()
			}
			n := int(done.Add(1))
			if progress != nil && (n%max(1, len(candidates)*len(ports)/100) == 0 || n == len(candidates)*len(ports)) {
				progress(n, total)
			}
		}
	}
	for i := 0; i < min(concurrency, max(1, len(candidates)*len(ports))); i++ {
		wg.Add(1)
		go worker()
	}
	go func() {
		defer close(jobs)
		for _, host := range candidates {
			for _, port := range ports {
				select {
				case jobs <- probe{host, port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	wg.Wait()
	if ctx.Err() == nil {
		for _, host := range confirmedNeighborHosts(ctx, candidates, live) {
			live[host] = true
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if progress != nil {
		progress(total, total)
	}
	var out []string
	for host := range live {
		out = append(out, host)
	}
	return uniqueSorted(out), nil
}

func pingHost(ctx context.Context, host string, timeout time.Duration) bool {
	ip := net.ParseIP(host)
	if ip == nil || ctx.Err() != nil {
		return false
	}
	network, local, protocol := "udp4", "0.0.0.0", 1
	echoType, replyType := icmp.Type(ipv4.ICMPTypeEcho), icmp.Type(ipv4.ICMPTypeEchoReply)
	if ip.To4() == nil {
		network, local, protocol = "udp6", "::", 58
		echoType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	var destination net.Addr = &net.UDPAddr{IP: ip}
	conn, err := icmp.ListenPacket(network, local)
	if err != nil {
		rawNetwork := "ip4:icmp"
		if ip.To4() == nil {
			rawNetwork = "ip6:ipv6-icmp"
		}
		conn, err = icmp.ListenPacket(rawNetwork, local)
		if err != nil {
			return systemPing(ctx, ip.String(), timeout)
		}
		destination = &net.IPAddr{IP: ip}
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopCancel()
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	seq := int(pingSequence.Add(1) & 0xffff)
	identifier := os.Getpid() & 0xffff
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		identifier = addr.Port
	}
	request := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{ID: identifier, Seq: seq, Data: []byte("wscan")},
	}
	packet, err := request.Marshal(nil)
	if err != nil {
		return false
	}
	if _, err = conn.WriteTo(packet, destination); err != nil {
		return false
	}
	buffer := make([]byte, 1500)
	for {
		n, peer, readErr := conn.ReadFrom(buffer)
		if readErr != nil || ctx.Err() != nil {
			return false
		}
		var senderIP net.IP
		switch sender := peer.(type) {
		case *net.IPAddr:
			senderIP = sender.IP
		case *net.UDPAddr:
			senderIP = sender.IP
		}
		if !senderIP.Equal(ip) {
			continue
		}
		message, parseErr := icmp.ParseMessage(protocol, buffer[:n])
		if parseErr != nil || message.Type != replyType {
			continue
		}
		echo, ok := message.Body.(*icmp.Echo)
		if ok && echo.ID == identifier && echo.Seq == seq && bytes.Equal(echo.Data, []byte("wscan")) {
			return true
		}
	}
}

func uniqueSorted(in []string) []string {
	set := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !set[s] {
			set[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// systemPing uses the installed ping's network privileges without elevating
// the scanner. A bounded context limits even platforms with coarse timeouts.
func systemPing(ctx context.Context, host string, timeout time.Duration) bool {
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var args []string
	switch runtime.GOOS {
	case "windows":
		args = []string{"-n", "1", "-w", fmt.Sprint(max(1, timeout.Milliseconds())), host}
	case "darwin", "freebsd":
		args = []string{"-n", "-c", "1", "-W", fmt.Sprint(max(1, timeout.Milliseconds())), host}
	default:
		args = []string{"-n", "-c", "1", "-W", fmt.Sprint(max(1, int((timeout+time.Second-1)/time.Second))), host}
	}
	return exec.CommandContext(pingCtx, "ping", args...).Run() == nil
}
