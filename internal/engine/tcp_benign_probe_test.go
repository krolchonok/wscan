package engine

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"wscan/internal/domain"
	tpl "wscan/internal/template"
)

func loadUpstreamNetworkTemplate(t *testing.T, sub, name string) domain.Template {
	t.Helper()
	for _, c := range []string{
		filepath.Join("..", "..", "library", "nuclei-templates", "network", sub),
		filepath.Join("library", "nuclei-templates", "network", sub),
	} {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			raw, err := os.ReadFile(filepath.Join(c, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			tm, err := tpl.ForExecution(raw, "network/"+sub+"/"+name)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			if !tm.Compatible {
				t.Fatalf("%s not compatible: %v", name, tm.Unsupported)
			}
			return tm
		}
	}
	t.Fatalf("library/nuclei-templates/network/%s/%s not found", sub, name)
	return domain.Template{}
}

// TestNFSv3ExposedClosedPortIsQuietNotAnError reproduces "Ошибка проверки:
// nfs-v3-exposed 10.0.0.10:2049: dial tcp 10.0.0.10:2049: connect: connection
// refused". nuclei's network (tcp:) protocol has no pre-condition mechanism
// — dialing the template's own port:2049 IS the probe — so a host that
// simply isn't running NFS hits this on every single scan. That's the normal
// "not present here" outcome, not a defect (see isBenignTCPProbeError).
func TestNFSv3ExposedClosedPortIsQuietNotAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listening now

	tmpl := loadUpstreamNetworkTemplate(t, "detection", "nfs-v3-exposed.yaml")
	for i := range tmpl.TCP {
		tmpl.TCP[i].Port = []int{port}
	}

	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"127.0.0.1"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("closed NFS port must not surface as a check error, got: %v", res.Errors)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("closed NFS port must not match, got %d findings", len(res.Findings))
	}
}

// Negative: isBenignTCPProbeError must not swallow a genuinely different
// failure.
func TestIsBenignTCPProbeErrorDoesNotMatchOtherErrors(t *testing.T) {
	cases := []struct {
		msg    string
		benign bool
	}{
		{"dial tcp 10.0.0.10:2049: connect: connection refused", true},
		{"read tcp 10.0.0.10:1666: i/o timeout", true},
		{"dial tcp: lookup nosuchhost.invalid: no such host", false},
		{"invalid hex input: encoding/hex: odd length hex string", false},
	}
	for _, c := range cases {
		got := isBenignTCPProbeError(&testError{c.msg})
		if got != c.benign {
			t.Errorf("isBenignTCPProbeError(%q) = %v, want %v", c.msg, got, c.benign)
		}
	}
}
