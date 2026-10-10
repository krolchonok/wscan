package js

import (
	"context"
	"strings"
)

// DiscoveredService is the minimal per-service shape a javascript: check
// needs to find "whatever port our own scanner already identified as X on
// this host" — a local, dependency-light stand-in for domain.Service (this
// package stays free of the domain import; the caller converts).
type DiscoveredService struct {
	Host string
	Port int
	Name string
}

type servicesContextKey struct{}

// WithDiscoveredServices attaches the project's discovered services to ctx.
// Because every javascript: execution path (execTemplate -> execJavaScript
// -> Run) derives its context from the same scan-level ctx, setting this
// once per scan makes it available to every check's goja VM via
// discoveredPorts(...) without threading a new parameter through each of
// those call sites.
func WithDiscoveredServices(ctx context.Context, services []DiscoveredService) context.Context {
	return context.WithValue(ctx, servicesContextKey{}, services)
}

func discoveredServicesFrom(ctx context.Context) []DiscoveredService {
	v, _ := ctx.Value(servicesContextKey{}).([]DiscoveredService)
	return v
}

// portsFor returns the ports discovered for host whose Name contains
// namePattern (case-insensitive substring match — e.g. "microsoft-ds" or
// "smb"), in the order they were discovered. Used instead of a hardcoded
// port list (e.g. a literal 445/4445 guess) so a check reaches exactly
// whatever port our own active identification (see
// internal/discovery/smb_identify.go) actually found, on any port number.
func portsFor(services []DiscoveredService, host, namePattern string) []int {
	namePattern = strings.ToLower(namePattern)
	var ports []int
	for _, s := range services {
		if !strings.EqualFold(s.Host, host) {
			continue
		}
		if namePattern != "" && !strings.Contains(strings.ToLower(s.Name), namePattern) {
			continue
		}
		ports = append(ports, s.Port)
	}
	return ports
}
