package js

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestPortsForFiltersByHostAndNamePattern(t *testing.T) {
	services := []DiscoveredService{
		{Host: "10.0.0.133", Port: 445, Name: "microsoft-ds"},
		{Host: "10.0.0.133", Port: 4445, Name: "microsoft-ds"},
		{Host: "10.0.0.133", Port: 80, Name: "http"},
		{Host: "10.0.0.10", Port: 445, Name: "microsoft-ds"},
	}
	got := portsFor(services, "10.0.0.133", "microsoft-ds")
	want := []int{445, 4445}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("portsFor = %v, want %v", got, want)
	}
}

func TestPortsForEmptyPatternMatchesEverythingOnHost(t *testing.T) {
	services := []DiscoveredService{
		{Host: "10.0.0.133", Port: 445, Name: "microsoft-ds"},
		{Host: "10.0.0.133", Port: 80, Name: "http"},
	}
	got := portsFor(services, "10.0.0.133", "")
	want := []int{445, 80}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("portsFor = %v, want %v", got, want)
	}
}

func TestPortsForNoMatchReturnsNil(t *testing.T) {
	services := []DiscoveredService{{Host: "10.0.0.133", Port: 80, Name: "http"}}
	got := portsFor(services, "10.0.0.133", "microsoft-ds")
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

// TestDiscoveredPortsGlobalReadsFromContext proves the discoveredPorts(...)
// global a template calls is actually wired to WithDiscoveredServices, not
// just the pure portsFor helper — this is the part that previously didn't
// exist at all (CVE-2017-0143.yaml/CVE-2008-4250.yaml hardcoded "445"/"4445"
// literals instead of asking the scanner what it actually found).
func TestDiscoveredPortsGlobalReadsFromContext(t *testing.T) {
	ctx := WithDiscoveredServices(context.Background(), []DiscoveredService{
		{Host: "10.0.0.133", Port: 4445, Name: "microsoft-ds"},
		{Host: "10.0.0.133", Port: 80, Name: "http"},
	})
	res := Run(ctx, `Export(JSON.stringify(discoveredPorts("10.0.0.133", "microsoft-ds")));`, "", nil, nil, "", 5*time.Second)
	if !res.Success {
		t.Fatalf("expected success, err=%q", res.Error)
	}
	if res.Response != "[4445]" {
		t.Fatalf("discoveredPorts = %v, want [4445]", res.Response)
	}
}

func TestDiscoveredPortsGlobalEmptyWithoutContext(t *testing.T) {
	res := Run(context.Background(), `Export(discoveredPorts("10.0.0.133", "microsoft-ds").length);`, "", nil, nil, "", 5*time.Second)
	if !res.Success {
		t.Fatalf("expected success, err=%q", res.Error)
	}
	if res.Response != "0" {
		t.Fatalf("expected 0 with no services attached, got %v", res.Response)
	}
}
