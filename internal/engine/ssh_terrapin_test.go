package engine

import (
	"context"
	"fmt"
	"testing"

	"wscan/internal/domain"
)

// TestCVE202348795RunsEndToEndWithoutCrashing is the full-template
// regression for the "Cannot read property 'CiphersClientServer' of
// undefined" crash: runs the real, unmodified upstream CVE-2023-48795.yaml
// (Terrapin attack) against a fake SSH server exercising a real KEX
// handshake. The fake server's default x/crypto/ssh algorithm set includes
// no "kex-strict-s-v00@openssh.com" extension, so IsVulnerable() should
// legitimately evaluate false/undefined — the point of this test is only
// that ServerKex is populated and the script runs to completion instead of
// throwing before ever reaching the matcher.
func TestCVE202348795RunsEndToEndWithoutCrashing(t *testing.T) {
	port := fakeSSHPasswordServer(t, "root", "hunter2")
	tmpl := loadUpstreamJSTemplate(t, "cves/2023", "CVE-2023-48795.yaml")
	tmpl = withJSPort(tmpl, port)

	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 10})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{fmt.Sprintf("http://127.0.0.1:%d", port)}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("ServerKex must be populated, got check errors: %v", res.Errors)
	}
}
