package discovery

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
	"wscan/internal/domain"
)

func TestTLSSignatureDoesNotInventHTTP(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nmap"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nmap/nmap-service-probes"), []byte("Probe TCP NULL q||\nmatch ssl m|^TLS banner$|\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("TLS banner"))
			_ = c.Close()
		}
	}()
	for _, name := range []string{"rdp", ""} {
		service := domain.Service{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Protocol: "tcp", Name: name}
		got := identifyProbeService(context.Background(), service, root, time.Second, nil)
		if got.Tunnel != "ssl" || got.Name == "https" {
			t.Fatalf("TLS became HTTP: %+v", got)
		}
		if name == "rdp" && got.Name != "rdp" {
			t.Fatalf("lost RDP identity: %+v", got)
		}
		if url, ok := WebURL(got); ok {
			t.Fatalf("non-HTTP endpoint routed to Web checks: %s", url)
		}
	}
}

func TestRPCOverHTTPIsExcludedFromWebChecks(t *testing.T) {
	for _, name := range []string{"ncacn_http", "rpc-http"} {
		s := domain.Service{Host: "192.0.2.1", Port: 593, Protocol: "tcp", Name: name}
		if isHTTPService(s) {
			t.Fatal("RPC identified as Web", name)
		}
		if url, ok := WebURL(s); ok {
			t.Fatal("RPC routed to Web checks", url)
		}
	}
	for _, name := range []string{"http", "https", "winrm", "wsman", "wsmans"} {
		if _, ok := WebURL(domain.Service{Host: "192.0.2.1", Port: 5985, Protocol: "tcp", Name: name}); !ok {
			t.Fatal("lost Web endpoint", name)
		}
	}
}
