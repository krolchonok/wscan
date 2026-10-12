package adscan

import (
	"context"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPortOwnerInodesScope(t *testing.T) {
	data := []byte("0: 1000000A:01BD 00000000:0000 0A 0:0 0:0 0 0 0 111\n1: 1100000A:01BD 00000000:0000 0A 0:0 0:0 0 0 0 222\n2: 00000000:01BD 00000000:0000 0A 0:0 0:0 0 0 0 333\n3: 1000000A:01BD 00000000:0000 01 0:0 0:0 0 0 0 444\n4: 1000000A:008B 00000000:0000 0A 0:0 0:0 0 0 0 555\n")
	got := listeningInodes(data, net.ParseIP("10.0.0.16"))
	if len(got) != 2 || !got["111"] || !got["333"] {
		t.Fatalf("wrong owner scope: %v", got)
	}
}
func TestPortOwnerCancelledStopDoesNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StopCoercionPortOwners(ctx, "127.0.0.1", nil); err != context.Canceled {
		t.Fatalf("expected cancellation: %v", err)
	}
}
func TestPortOwnerProcessIdentity(t *testing.T) {
	owner, err := readPortProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if owner.PID != os.Getpid() || owner.Name == "" || owner.StartTime == "" {
		t.Fatalf("missing process identity: %+v", owner)
	}
}

// Opt-in local integration check; never stops a service in ordinary go test.
func TestPortOwnerSambaLive(t *testing.T) {
	ip := os.Getenv("WSCAN_TEST_SAMBA_IP")
	if ip == "" {
		t.Skip("explicit local Samba test not requested")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration check requires root")
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", "smbd").Run(); err != nil {
		t.Fatal("Samba must be active before test")
	}
	owners, err := CheckCoercionPort(ip)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, owner := range owners {
		if owner.Service == "smbd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no system Samba owner: %+v", owners)
	}
	// Independent restoration also covers a fatal assertion in this test.
	defer func() {
		if err := exec.Command("systemctl", "start", "smbd").Run(); err != nil {
			t.Errorf("restore Samba: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	lease, err := StopCoercionPortOwners(ctx, ip, owners)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Restore()
	free, err := CheckCoercionPort(ip)
	if err != nil || len(free) != 0 {
		t.Fatalf("port remains occupied: %v %v", free, err)
	}
	if err := lease.Restore(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", "smbd").Run(); err != nil {
		t.Fatal("Samba not restored")
	}
	t.Log("Samba stopped, TCP/445 released, service restored")
}
