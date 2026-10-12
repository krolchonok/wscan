package adscan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var responderSessions = struct {
	sync.Mutex
	receivers map[string]*coercionReceiver
}{receivers: map[string]*coercionReceiver{}}

func receiverForCoercion(ctx context.Context, ip string, allowed map[string]bool) (*coercionReceiver, bool, error) {
	responderSessions.Lock()
	defer responderSessions.Unlock()
	if r := responderSessions.receivers[ip]; r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		for host := range allowed {
			if !r.allowed[host] {
				return nil, false, fmt.Errorf("%s не входит в область запущенного приёмника; перезапусти приёмник с нужными целями", host)
			}
		}
		return r, false, nil
	}
	r, e := startCoercionReceiver(ctx, ip, allowed)
	return r, true, e
}

// RunResponder holds a standalone receiver until cancellation. It never causes
// remote authentication itself. Coerce jobs in the same process can reuse it.
func RunResponder(ctx context.Context, callback string, targets []string, progress func(string)) ([]AccessReport, error) {
	ip := net.ParseIP(strings.TrimSpace(callback))
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, fmt.Errorf("укажи локальный IPv4 приёмника")
	}
	addrs, e := net.InterfaceAddrs()
	if e != nil {
		return nil, e
	}
	local := false
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			local = true
		}
	}
	if !local {
		return nil, fmt.Errorf("адрес %s не назначен локальному интерфейсу", ip)
	}
	if len(targets) == 0 || len(targets) > 4096 {
		return nil, fmt.Errorf("выбери 1–4096 машин для приёмника")
	}
	allowed := map[string]bool{}
	for _, h := range targets {
		if h == "" || strings.ContainsAny(h, "/\\ \t\r\n") {
			return nil, fmt.Errorf("некорректная цель")
		}
		c, cancel := context.WithTimeout(ctx, 4*time.Second)
		addresses, err := net.DefaultResolver.LookupIPAddr(c, h)
		cancel()
		if err != nil {
			return nil, err
		}
		for _, a := range addresses {
			if a.IP.To4() != nil {
				if !a.IP.Equal(ip) {
					allowed[a.IP.String()] = true
				}
				break
			}
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("в списке нет удалённых IPv4 машин; адрес приёмника исключён")
	}
	responderSessions.Lock()
	if responderSessions.receivers[ip.String()] != nil {
		responderSessions.Unlock()
		return nil, fmt.Errorf("приёмник %s уже запущен", ip)
	}
	r, err := startCoercionReceiver(ctx, ip.String(), allowed)
	if err != nil {
		responderSessions.Unlock()
		return nil, err
	}
	r.mu.Lock()
	r.observe = func(host string, event coercionEvent) {
		if progress != nil {
			progress(fmt.Sprintf("Responder · %s · %s · %s", host, event.Stage, event.Identity))
		}
	}
	r.mu.Unlock()
	responderSessions.receivers[ip.String()] = r
	responderSessions.Unlock()
	if progress != nil {
		progress(fmt.Sprintf("Responder слушает %s:445 · %d машин", ip, len(allowed)))
	}
	<-ctx.Done()
	responderSessions.Lock()
	delete(responderSessions.receivers, ip.String())
	r.close()
	responderSessions.Unlock()
	reports := []AccessReport{}
	for host := range allowed {
		report := AccessReport{Host: host, Mode: "responder"}
		events := r.since(host, time.Time{})
		for _, event := range events {
			severity := "info"
			if event.Stage == "ntlm-authenticate" {
				severity = "high"
			}
			report.add("responder/"+event.Stage, "Responder · "+event.Stage, "observed", severity, fmt.Sprintf("%s · %s; идентичность заявлена клиентом, ответ криптографически не проверен", event.Time.Format(time.RFC3339Nano), event.Identity))
		}
		if len(events) == 0 {
			report.add("responder/callback", "Responder · обратное соединение", "incomplete", "info", "Событий не получено; уязвимость не оценена")
		}
		reports = append(reports, report)
	}
	return reports, nil
}
