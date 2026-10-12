//go:build !linux

package adscan

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestReceiverPortInvalidAndCancelled(t *testing.T) {
	for _, ip := range []string{"", "0.0.0.0", "224.0.0.1", "::1"} {
		if _, err := CheckCoercionPort(ip); err == nil {
			t.Fatalf("invalid IPv4 accepted: %q", ip)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StopCoercionPortOwners(ctx, "127.0.0.1", nil); err != context.Canceled {
		t.Fatalf("cancelled stop: %v", err)
	}
}

func TestOccupiedReceiverPortDoesNotOfferSystemServiceTermination(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:445")
	if err == nil {
		defer listener.Close()
	}
	// If binding failed, the port is already occupied or unavailable. Both cases
	// must report an error rather than exposing an automatic stop confirmation.
	owners, err := CheckCoercionPort("127.0.0.1")
	if err == nil || len(owners) != 0 || !strings.Contains(err.Error(), "445") {
		t.Fatalf("occupied port: owners=%v err=%v", owners, err)
	}
	if _, err := StopCoercionPortOwners(context.Background(), "127.0.0.1", nil); err == nil {
		t.Fatal("occupied port was silently approved")
	}
	if err := RestoreCoercionPorts(); err != nil {
		t.Fatal(err)
	}
}
