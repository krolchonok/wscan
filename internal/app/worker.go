// Package app owns execution independently of terminal and HTTP transports.
package app

import (
	"context"
	"fmt"
	"net"
	"strings"

	"wscan/internal/adscan"
	"wscan/internal/catalog"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/storage"
)

type Reporter func(stage string, counts ...int)
type RunFunc func(context.Context, Reporter) (engine.Result, error)

type Spec struct {
	Kind          string           `json:"kind"`
	Label         string           `json:"label"`
	Hosts         []string         `json:"hosts"`
	TemplateIDs   []string         `json:"template_ids"`
	Service       *domain.Service  `json:"service,omitempty"`
	Services      []domain.Service `json:"services,omitempty"`
	DNSServer     string           `json:"dns_server,omitempty"`
	DiscPorts     []int            `json:"ports,omitempty"`
	DiscUDPPorts  []int            `json:"udp_ports,omitempty"`
	DiscAllPorts  bool             `json:"all_ports,omitempty"`
	DiscSkipTCP   bool             `json:"skip_tcp,omitempty"`
	DiscNoVersion bool             `json:"no_version,omitempty"`
	DiscOnlyKnown bool             `json:"only_known,omitempty"`
	DiscNoPing    bool             `json:"no_ping,omitempty"`
}

type Worker struct {
	store            *storage.Store
	cat              *catalog.Catalog
	scanner          *engine.Engine
	current          domain.Project
	entries          []catalog.Entry
	services         []domain.Service
	adScanNewProject bool
	adScanDNS        adscan.DNSOptions
}

func NewWorker(s *storage.Store, c *catalog.Catalog, scan *engine.Engine, p domain.Project, entries []catalog.Entry, services []domain.Service, newProject bool, dns adscan.DNSOptions) Worker {
	p.Targets = append([]string(nil), p.Targets...)
	p.TemplateIDs = append([]string(nil), p.TemplateIDs...)
	return Worker{store: s, cat: c, scanner: scan, current: p, entries: append([]catalog.Entry(nil), entries...), services: append([]domain.Service(nil), services...), adScanNewProject: newProject, adScanDNS: dns}
}
func (m Worker) Build(spec Spec) RunFunc {
	switch spec.Kind {
	case "discover":
		return m.runDiscover(spec)
	case "alive-hosts":
		return m.runAliveHosts(spec)
	case "ptr":
		return m.runPTR(spec)
	case "checks":
		return m.runChecks(spec.Hosts, spec.TemplateIDs)
	case "full":
		return m.runFull(spec.Hosts)
	case "bulk-port":
		return m.runServiceChecks(spec.Services, spec.TemplateIDs)
	case "port":
		if spec.Service != nil {
			return m.runPortChecks(*spec.Service, spec.TemplateIDs)
		}
	}
	return func(context.Context, Reporter) (engine.Result, error) {
		return engine.Result{}, fmt.Errorf("unknown action %q", spec.Kind)
	}
}
func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
func serviceHostBucket(s domain.Service, targets []string) string {
	if s.Target != "" {
		if h, err := discovery.TargetHost(s.Target); err == nil && h != "" {
			return h
		}
		if s.Host != "" {
			return s.Host
		}
		return s.Target
	}
	if s.Host != "" {
		return s.Host
	}
	if len(targets) == 1 {
		return targets[0]
	}
	return s.Host
}
func (m Worker) servicesFor(host string) []domain.Service {
	var out []domain.Service
	_, network, networkErr := net.ParseCIDR(host)
	for _, s := range m.services {
		if networkErr == nil && network.Contains(net.ParseIP(s.Host)) || s.Host == host || serviceHostBucket(s, nil) == host {
			out = append(out, s)
		}
	}
	return out
}
func (m Worker) knownServices(hosts []string) []domain.Service {
	var out []domain.Service
	seen := map[string]bool{}
	for _, h := range hosts {
		for _, s := range m.servicesFor(h) {
			key := fmt.Sprintf("%s|%s|%d|%s", s.Host, s.Target, s.Port, s.Protocol)
			if !seen[key] {
				seen[key] = true
				out = append(out, s)
			}
		}
	}
	return out
}
func (m Worker) knownWebTargets(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		for _, s := range m.servicesFor(h) {
			if u, ok := discovery.WebURL(s); ok {
				out = append(out, u)
			}
		}
	}
	for _, target := range m.current.Targets {
		if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
			h, _ := discovery.TargetHost(target)
			for _, selected := range hosts {
				if h == selected {
					out = append(out, target)
				}
			}
		}
	}
	return uniqueStrings(out)
}

type reportingChecks struct {
	engine *engine.Engine
	emit   Reporter
}

func (r reportingChecks) Scan(ctx context.Context, p domain.Project, ts []domain.Template) (engine.Result, error) {
	r.emit("Проверки шаблонов")
	return r.engine.ScanProgress(ctx, p, ts, func(d, t int) { r.emit("Проверки шаблонов", d, t) })
}
