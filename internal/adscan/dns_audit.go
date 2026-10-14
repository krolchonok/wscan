package adscan

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// AuditDNS checks only the selected server/zone from this scanner's address.
// RA is an advertised capability; it does not establish Internet-wide access.
func AuditDNS(ctx context.Context, host, zone string, port int, timeout time.Duration) (AccessReport, error) {
	return auditDNS(ctx, host, zone, port, timeout, nil)
}

func auditDNS(ctx context.Context, host, zone string, port int, timeout time.Duration, progress func(string)) (AccessReport, error) {
	r := AccessReport{Host: host, Mode: "dns"}
	if port == 0 {
		port = 53
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	name, e := dnsmessage.NewName(strings.TrimSuffix(strings.TrimSpace(zone), ".") + ".")
	if e != nil || zone == "" {
		return r, fmt.Errorf("укажи корректную DNS-зону")
	}
	r.Endpoint = "tcp://" + net.JoinHostPort(host, strconv.Itoa(port))
	if progress != nil {
		progress("DNS AXFR · " + r.Endpoint + " · зона " + name.String() + " · timeout=" + timeout.String())
	}
	started := time.Now()
	count, state, evidence := auditAXFR(ctx, host, port, name, timeout)
	if progress != nil {
		progress(fmt.Sprintf("DNS AXFR · state=%s records=%d elapsed=%s · %s", state, count, time.Since(started).Round(time.Millisecond), evidence))
	}
	r.add("dns-axfr", "DNS AXFR", state, func() string {
		if state == "confirmed" {
			return "medium"
		}
		return "info"
	}(), fmt.Sprintf("%s; записей: %d; область: %s", evidence, count, name.String()))
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if progress != nil {
		progress("DNS · объявленная рекурсия · " + r.Endpoint)
	}
	c, id, e := dnsAuditConnection(qctx, host, port, dnsmessage.Question{Name: name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}, true)
	if e != nil {
		r.add("dns-recursion", "DNS recursion capability", "error", "info", e.Error())
		return r, ctx.Err()
	}
	defer c.Close()
	stop := context.AfterFunc(qctx, func() { _ = c.Close() })
	defer stop()
	started = time.Now()
	m, e := readDNSMessage(c, id)
	e = accessFailure("DNS SOA read response "+r.Endpoint, started, e)
	if e != nil {
		r.add("dns-recursion", "DNS recursion capability", "error", "info", e.Error())
	} else if m.Header.RecursionAvailable {
		r.add("dns-recursion", "DNS recursion capability", "candidate", "info", "RA=1: сервер объявляет рекурсию этому клиенту. Произвольные внешние имена и доступ из других подсетей не проверены.")
	} else {
		r.add("dns-recursion", "DNS recursion capability", "negative", "info", "RA=0 в ответе выбранному клиенту; глобальная политика неизвестна")
	}
	if progress != nil && e == nil {
		progress(fmt.Sprintf("DNS SOA · RCODE=%d RA=%t AA=%t elapsed=%s", m.Header.RCode, m.Header.RecursionAvailable, m.Header.Authoritative, time.Since(started).Round(time.Millisecond)))
	}
	return r, ctx.Err()
}

func dnsAuditConnection(ctx context.Context, host string, port int, q dnsmessage.Question, recursive bool) (net.Conn, uint16, error) {
	started := time.Now()
	endpoint := net.JoinHostPort(host, strconv.Itoa(port))
	var seed [2]byte
	if _, e := rand.Read(seed[:]); e != nil {
		return nil, 0, e
	}
	id := binary.BigEndian.Uint16(seed[:])
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: recursive}, Questions: []dnsmessage.Question{q}}
	packet, e := msg.Pack()
	if e != nil {
		return nil, 0, e
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if e != nil {
		return nil, 0, accessFailure("DNS TCP connect "+endpoint, started, e)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(len(packet)))
	packet = append(h, packet...)
	if _, e = c.Write(packet); e != nil {
		c.Close()
		return nil, 0, accessFailure("DNS TCP send query "+endpoint, started, e)
	}
	return c, id, nil
}
func readDNSMessage(r io.Reader, id uint16) (dnsmessage.Message, error) {
	var m dnsmessage.Message
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return m, e
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 12 {
		return m, fmt.Errorf("DNS packet too short")
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return m, e
	}
	if e := m.Unpack(b); e != nil {
		return m, e
	}
	if m.Header.ID != id || !m.Header.Response || m.Header.Truncated {
		return m, fmt.Errorf("invalid/truncated DNS response")
	}
	return m, nil
}

func auditAXFR(ctx context.Context, host string, port int, name dnsmessage.Name, timeout time.Duration) (int, string, string) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, id, e := dnsAuditConnection(ctx, host, port, dnsmessage.Question{Name: name, Type: dnsmessage.Type(252), Class: dnsmessage.ClassINET}, false)
	if e != nil {
		return 0, "error", e.Error()
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	count := 0
	started := time.Now()
	var first *dnsmessage.SOAResource
	for messages := 0; messages < 128; messages++ {
		m, e := readDNSMessage(c, id)
		if e != nil {
			e = accessFailure(fmt.Sprintf("DNS AXFR read response %s:%d messages=%d records=%d", host, port, messages, count), started, e)
			state := "error"
			if count > 0 {
				state = "incomplete"
			}
			return count, state, e.Error()
		}
		if m.Header.RCode == dnsmessage.RCodeRefused {
			return count, "denied", "Сервер отказал в AXFR"
		}
		if m.Header.RCode != dnsmessage.RCodeSuccess {
			return count, "incomplete", fmt.Sprintf("DNS RCODE=%d", m.Header.RCode)
		}
		for _, q := range m.Questions {
			if !strings.EqualFold(q.Name.String(), name.String()) || q.Type != 252 || q.Class != dnsmessage.ClassINET {
				return count, "error", "AXFR question mismatch"
			}
		}
		if len(m.Answers) == 0 {
			return count, "incomplete", "Пустой ответ AXFR"
		}
		for _, answer := range m.Answers {
			count++
			if count > 4096 {
				return count, "incomplete", "Лимит записей AXFR достигнут"
			}
			soa, ok := answer.Body.(*dnsmessage.SOAResource)
			if count == 1 {
				if !ok || !strings.EqualFold(answer.Header.Name.String(), name.String()) {
					return count, "error", "AXFR не начинается с SOA запрошенной зоны"
				}
				first = soa
				continue
			}
			if ok && strings.EqualFold(answer.Header.Name.String(), name.String()) {
				if first == nil || soa.Serial != first.Serial || soa.NS != first.NS || soa.MBox != first.MBox {
					return count, "incomplete", "SOA в конце AXFR не совпадает с начальной"
				}
				return count, "confirmed", "Полный AXFR доступен без авторизации с адреса сканера; DNS-записи не изменялись"
			}
		}
	}
	return count, "incomplete", "Лимит DNS-сообщений достигнут"
}
