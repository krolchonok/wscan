package engine

import (
	"context"
	"net"
	"testing"

	"wscan/internal/domain"
)

// TestTFTPDetectClosedPortIsQuietNotAnError reproduces the real run's
// "tftp-detect: read udp 10.0.0.10:...->10.0.0.10:69: read: connection
// refused" surfacing as a check error. isUDPPortOpen can't tell a UDP port
// is closed (the dial itself always succeeds), so tftp-detect.yaml's probe
// reaches RecvString and only learns the port is closed from the kernel's
// ICMP port-unreachable turning into a "connection refused" read error. That
// must be a quiet non-match, not a check error — see isBenignUDPRefusal.
func TestTFTPDetectClosedPortIsQuietNotAnError(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := ln.LocalAddr().(*net.UDPAddr).Port
	ln.Close() // nothing listening now; the kernel ICMP-rejects datagrams here

	tmpl := loadUpstreamJSTemplate(t, "udp/detection", "tftp-detect.yaml")
	tmpl = withJSPort(tmpl, port)

	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"127.0.0.1"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("closed UDP port must not surface as a check error, got: %v", res.Errors)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("closed UDP port must not match, got %d findings", len(res.Findings))
	}
}

// Negative: a non-UDP "connection refused" (template ran past a closed TCP
// port's precondition) must still be reported — isBenignUDPRefusal must not
// swallow that real problem. Mirrors
// TestSSHDefaultLoginsConnectionRefusedStillErrors but exercises the helper
// directly against raw error text, since constructing a second live TCP
// fixture here would just duplicate that test.
func TestIsBenignUDPRefusalDoesNotMatchTCP(t *testing.T) {
	tcpErr := "dial tcp 127.0.0.1:9: connect: connection refused"
	if isBenignUDPRefusal(tcpErr) {
		t.Fatalf("TCP connection refused must not be treated as a benign UDP refusal: %q", tcpErr)
	}
	udpErr := "read udp 127.0.0.1:54321->127.0.0.1:69: read: connection refused"
	if !isBenignUDPRefusal(udpErr) {
		t.Fatalf("UDP connection refused must be treated as benign: %q", udpErr)
	}
}
