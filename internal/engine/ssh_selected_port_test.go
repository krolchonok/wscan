package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"wscan/internal/domain"
)

// Use the library templates as-is: changing their ports in the test would
// conceal a regression back to the template's hard-coded port 22.
func TestSSHLibraryTemplatesUseSelectedPort(t *testing.T) {
	port := fakeSSHPasswordServer(t, "root", "test-password")
	if port == 22 {
		t.Fatal("test requires a nonstandard SSH port")
	}
	target := fmt.Sprintf("http://127.0.0.1:%d", port)
	for _, template := range []domain.Template{
		loadUpstreamJSTemplate(t, "enumeration/ssh", "ssh-password-auth.yaml"),
		loadUpstreamJSTemplate(t, "detection", "ssh-auth-methods.yaml"),
		loadMSFTemplate(t, "msf-ssh-ssh-version.yaml"),
	} {
		t.Run(template.ID, func(t *testing.T) {
			e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 1, TimeoutSeconds: 3})
			res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{target}}, []domain.Template{template})
			if err != nil || len(res.Errors) != 0 || len(res.Findings) == 0 {
				t.Fatalf("findings=%v errors=%v error=%v", res.Findings, res.Errors, err)
			}
			for _, finding := range res.Findings {
				if !strings.Contains(finding.MatchedAt, fmt.Sprintf(":%d", port)) {
					t.Fatalf("finding left selected port: %s", finding.MatchedAt)
				}
			}
		})
	}
}
