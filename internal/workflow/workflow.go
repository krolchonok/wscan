// Package workflow connects discovery modules to protocol-specific check engines.
package workflow

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"

	"wscan/internal/discovery"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

type Discovery interface {
	Scan(context.Context, string) ([]domain.Service, error)
}

type Checks interface {
	Scan(context.Context, domain.Project, []domain.Template) (engine.Result, error)
}

type Runner struct {
	Discovery Discovery
	HTTP      Checks
}

func (r Runner) Run(ctx context.Context, project domain.Project, templates []domain.Template) (engine.Result, error) {
	if !project.DiscoveryEnabled {
		return r.HTTP.Scan(ctx, project, templates)
	}
	project.UseDiscoveredTargets = true
	project.ScanTargets = nil
	project.Services = nil
	targets := make([]string, 0, len(project.Targets))
	for _, target := range project.Targets {
		if discovery.IsNetworkTarget(target) {
			addresses, err := discovery.ExpandCIDR(target)
			if err != nil {
				return engine.Result{}, err
			}
			targets = append(targets, addresses...)
		} else {
			targets = append(targets, target)
		}
	}
	var scanErrors []string
	for _, target := range unique(targets) {
		services, err := r.Discovery.Scan(ctx, target)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("discovery %s: %v", target, err))
			continue
		}
		for i := range services {
			services[i].Target = target
		}
		project.Services = append(project.Services, services...)
		addedWeb := false
		for _, service := range services {
			if web, ok := webURLForTarget(service, target); ok {
				project.ScanTargets = append(project.ScanTargets, web)
				addedWeb = true
			}
		}
		if isExplicitHTTPURL(target) {
			project.ScanTargets = append(project.ScanTargets, target)
			addedWeb = true
		}
		// Every selected template — http:, tcp:, javascript:, … — runs
		// against this same project.ScanTargets list; each non-HTTP request
		// carries its own port (an SMB javascript: check hardcodes 445, a
		// tcp: block has its own port:), so it doesn't need a web endpoint,
		// just a reachable host. Without this fallback, a host with real
		// open services but none classified as web (SMB/RDP/SSH-only, no
		// HTTP(S)) got zero scan targets at all — every template, including
		// the non-HTTP ones that had nothing to do with the missing web
		// server, silently never ran.
		if !addedWeb && len(services) > 0 {
			project.ScanTargets = append(project.ScanTargets, target)
		}
	}
	project.ScanTargets = unique(project.ScanTargets)
	result, err := r.HTTP.Scan(ctx, project, templates)
	if err != nil {
		return result, err
	}
	result.Errors = append(scanErrors, result.Errors...)
	return result, nil
}

func isExplicitHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func webURLForTarget(service domain.Service, original string) (string, bool) {
	web, ok := discovery.WebURL(service)
	if !ok {
		return "", false
	}
	host, err := discovery.TargetHost(original)
	if err != nil || net.ParseIP(host) != nil {
		return web, ok
	}
	u, err := url.Parse(web)
	if err != nil {
		return web, ok
	}
	u.Host = net.JoinHostPort(host, strconv.Itoa(service.Port))
	return u.String(), true
}
func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func DiscoverySummary(result engine.Result) string {
	return fmt.Sprintf("Found %d open TCP services; checked %d web endpoints.", len(result.Services), result.TargetsScanned)
}
