package discovery

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DNSServerAddress accepts an IP with an optional DNS port.
func DNSServerAddress(value string) (string, error) {
	if ip, err := netip.ParseAddr(value); err == nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("укажи IP DNS-сервера или IP:порт")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return "", fmt.Errorf("DNS-сервер должен быть IP-адресом")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("порт DNS: 1–65535")
	}
	return net.JoinHostPort(host, port), nil
}

// ScanPTR queries every address in the selected networks without liveness probes.
// Results include successful empty answers, but never cache transport failures.
func ScanPTR(ctx context.Context, networks []string, server string, concurrency, rps int, timeout time.Duration, progress func(int, int)) (map[string][]string, []string, error) {
	address, err := DNSServerAddress(server)
	if err != nil {
		return nil, nil, err
	}
	var hosts []string
	seen := map[string]bool{}
	for _, cidr := range networks {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid network %q", cidr)
		}
		// Bound enumeration before allocating, including IPv6 ranges.
		if prefix.Addr().BitLen()-prefix.Bits() > 16 {
			return nil, nil, fmt.Errorf("PTR: максимум 65536 адресов на подсеть")
		}
		prefix = prefix.Masked()
		for ip := prefix.Addr(); ip.IsValid() && prefix.Contains(ip); ip = ip.Next() {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			host := ip.String()
			if !seen[host] {
				seen[host] = true
				if len(hosts) == 65536 {
					return nil, nil, fmt.Errorf("PTR: максимум 65536 адресов за запуск")
				}
				hosts = append(hosts, host)
			}
		}
	}
	hosts = uniqueSorted(hosts)
	concurrency = min(64, max(1, concurrency))
	if rps <= 0 {
		rps = 100
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ticker := time.NewTicker(max(time.Nanosecond, time.Second/time.Duration(rps)))
	defer ticker.Stop()
	names := map[string][]string{}
	var failures []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)
	done := 0
	if progress != nil {
		progress(0, len(hosts))
	}
	for i := 0; i < min(concurrency, len(hosts)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				queryCtx, cancel := context.WithTimeout(ctx, timeout)
				values, queryErr := queryPTR(queryCtx, host, address, timeout)
				cancel()
				if ctx.Err() != nil {
					return
				}
				mu.Lock()
				var dnsErr *net.DNSError
				if queryErr == nil {
					var clean []string
					for _, value := range values {
						if value = strings.TrimSuffix(value, "."); value != "" {
							clean = append(clean, value)
						}
					}
					names[host] = uniqueSorted(clean)
				} else if errors.As(queryErr, &dnsErr) && dnsErr.IsNotFound {
					names[host] = nil
				} else {
					failures = append(failures, host+": "+queryErr.Error())
				}
				done++
				if progress != nil {
					progress(done, len(hosts))
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, host := range hosts {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- host:
		}
	}
	close(jobs)
	wg.Wait()
	return names, failures, ctx.Err()
}

// queryPTR goes directly to the selected server, bypassing /etc/hosts and the
// system resolver. Truncated UDP responses are retried over TCP.
func queryPTR(ctx context.Context, host, server string, timeout time.Duration) ([]string, error) {
	ip := netip.MustParseAddr(host)
	var reverse string
	if ip.Is4() {
		b := ip.As4()
		reverse = fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
	} else {
		b := ip.As16()
		const hex = "0123456789abcdef"
		var out strings.Builder
		for i := len(b) - 1; i >= 0; i-- {
			out.WriteByte(hex[b[i]&15])
			out.WriteByte('.')
			out.WriteByte(hex[b[i]>>4])
			out.WriteByte('.')
		}
		reverse = out.String() + "ip6.arpa."
	}
	qname, err := dnsmessage.NewName(reverse)
	if err != nil {
		return nil, err
	}
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(random[:])
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: qname, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}}}
	packet, err := request.Pack()
	if err != nil {
		return nil, err
	}
	for _, transport := range []string{"udp", "tcp"} {
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, transport, server)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		conn.SetDeadline(deadline)
		response, err := func() ([]byte, error) {
			defer conn.Close()
			if transport == "tcp" {
				frame := make([]byte, 2+len(packet))
				binary.BigEndian.PutUint16(frame, uint16(len(packet)))
				copy(frame[2:], packet)
				if _, err := io.Copy(conn, strings.NewReader(string(frame))); err != nil {
					return nil, err
				}
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return nil, err
				}
				buf := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				_, err := io.ReadFull(conn, buf)
				return buf, err
			}
			if _, err := conn.Write(packet); err != nil {
				return nil, err
			}
			buf := make([]byte, 65535)
			n, err := conn.Read(buf)
			return buf[:n], err
		}()
		stop()
		if err != nil {
			return nil, err
		}
		var answer dnsmessage.Message
		if err := answer.Unpack(response); err != nil {
			return nil, err
		}
		if answer.ID != id || !answer.Response || len(answer.Questions) != 1 || answer.Questions[0] != request.Questions[0] {
			return nil, fmt.Errorf("invalid DNS response")
		}
		if answer.Truncated && transport == "udp" {
			continue
		}
		if answer.Truncated {
			return nil, fmt.Errorf("truncated DNS TCP response")
		}
		if answer.RCode == dnsmessage.RCodeNameError {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		if answer.RCode != dnsmessage.RCodeSuccess {
			return nil, fmt.Errorf("DNS: %s", answer.RCode)
		}
		var names []string
		for _, resource := range answer.Answers {
			if ptr, ok := resource.Body.(*dnsmessage.PTRResource); ok {
				names = append(names, ptr.PTR.String())
			}
		}
		return names, nil
	}
	return nil, fmt.Errorf("no DNS response")
}
