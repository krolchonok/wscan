package adscan

import (
	"context"
	"net"
	"testing"
)

func TestExplicitADTargetsStayIndividualHosts(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	oldPorts := adPorts
	adPorts = []int{listener.Addr().(*net.TCPAddr).Port}
	defer func() { adPorts = oldPorts }()
	result, err := ScanTargets(context.Background(), []string{"127.0.0.1", "127.0.0.2", "127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.HostsScanned != 2 || len(result.Hosts) != 1 || result.Hosts[0].Address != "127.0.0.1" {
		t.Fatalf("scope mismatch: %+v", result)
	}
}

func TestADTargetValidationAcceptsHostLists(t *testing.T) {
	for _, targets := range [][]string{{"10.20.0.10", "10.20.0.11"}, {"dc.lab.example", "10.20.0.0/30"}, {"::1"}} {
		if err := ValidateTargets(targets); err != nil {
			t.Fatalf("%v: %v", targets, err)
		}
	}
	for _, targets := range [][]string{nil, {"http://dc.lab.example"}, {"10.20.0.10:389"}, {"invalid/path"}} {
		if err := ValidateTargets(targets); err == nil {
			t.Fatalf("accepted %v", targets)
		}
	}
}
