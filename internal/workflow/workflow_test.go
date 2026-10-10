package workflow

import (
	"context"
	"testing"

	"wscan/internal/domain"
	"wscan/internal/engine"
)

type fakeDiscovery struct {
	services []domain.Service
	err      error
}

func (f fakeDiscovery) Scan(context.Context, string) ([]domain.Service, error) {
	return f.services, f.err
}

type capturingChecks struct {
	got domain.Project
}

func (c *capturingChecks) Scan(_ context.Context, p domain.Project, _ []domain.Template) (engine.Result, error) {
	c.got = p
	return engine.Result{}, nil
}

// TestNonWebServicesStillGetAScanTarget reproduces the real gap: a host
// whose only discovered services are non-HTTP (SMB/RDP/SSH/…) used to get
// an empty ScanTargets — meaning every selected template, HTTP or not,
// silently never ran, since they all iterate the same ScanTargets list.
func TestNonWebServicesStillGetAScanTarget(t *testing.T) {
	checks := &capturingChecks{}
	r := Runner{
		Discovery: fakeDiscovery{services: []domain.Service{
			{Host: "10.0.0.10", Port: 445, Protocol: "tcp", Name: "smb"},
		}},
		HTTP: checks,
	}
	p := domain.Project{DiscoveryEnabled: true, Targets: []string{"10.0.0.10"}}
	if _, err := r.Run(context.Background(), p, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(checks.got.ScanTargets) != 1 || checks.got.ScanTargets[0] != "10.0.0.10" {
		t.Fatalf("ScanTargets = %v, want [\"10.0.0.10\"] (the bare host, as a fallback)", checks.got.ScanTargets)
	}
}

// Unchanged behavior: a host with a real web service still gets the actual
// web URL, not just the bare host (no regression from the fallback above).
func TestWebServiceStillProducesWebURL(t *testing.T) {
	checks := &capturingChecks{}
	r := Runner{
		Discovery: fakeDiscovery{services: []domain.Service{
			{Host: "10.0.0.10", Port: 80, Protocol: "tcp", Name: "http"},
		}},
		HTTP: checks,
	}
	p := domain.Project{DiscoveryEnabled: true, Targets: []string{"10.0.0.10"}}
	if _, err := r.Run(context.Background(), p, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := "http://10.0.0.10:80"
	if len(checks.got.ScanTargets) != 1 || checks.got.ScanTargets[0] != want {
		t.Fatalf("ScanTargets = %v, want [%q]", checks.got.ScanTargets, want)
	}
}

// A host where discovery found nothing at all (no open ports) still gets no
// scan target — that's a different, deliberate case (host unreachable/fully
// filtered), not the gap this fix addresses.
func TestNoServicesAtAllStaysEmpty(t *testing.T) {
	checks := &capturingChecks{}
	r := Runner{
		Discovery: fakeDiscovery{services: nil},
		HTTP:      checks,
	}
	p := domain.Project{DiscoveryEnabled: true, Targets: []string{"10.0.0.10"}}
	if _, err := r.Run(context.Background(), p, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(checks.got.ScanTargets) != 0 {
		t.Fatalf("ScanTargets = %v, want empty", checks.got.ScanTargets)
	}
}
