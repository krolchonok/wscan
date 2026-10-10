package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProgressCountsOpenClosedAndSilentPorts(t *testing.T) {
	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	var counts []int
	s := Scanner{Config: Config{Ports: []int{open.Addr().(*net.TCPAddr).Port, closedPort}, UDPPorts: []int{udp.LocalAddr().(*net.UDPAddr).Port}, RPS: 1000, Concurrency: 2, NoVersion: true, Timeout: 30 * time.Millisecond,
		Progress: func(target string, done, total int) {
			if target != "127.0.0.1" || total != 3 {
				t.Errorf("unexpected progress: %s %d/%d", target, done, total)
			}
			counts = append(counts, done)
		}}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	services, err := s.Scan(ctx, "127.0.0.1")
	if err != nil || len(services) != 1 {
		t.Fatalf("scan: %+v, %v", services, err)
	}
	if len(counts) != 4 {
		t.Fatalf("progress did not include every completed probe: %v", counts)
	}
	for i, n := range counts {
		if n != i {
			t.Fatalf("non-monotonic progress: %v", counts)
		}
	}
}
