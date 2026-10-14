package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/app"
	"wscan/internal/domain"
)

func TestDiagnosticExportWorksForRestoredFailureWithoutRun(t *testing.T) {
	m := newTestModelForSettings(t)
	m.appDir = t.TempDir()
	secret := "fixture-password-123"
	if _, err := m.store.CreateCredential(m.ctx, domain.Credential{ProjectID: m.current.ID, Type: "password", Username: "alice", Secret: secret}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(app.Job{ID: 8, JobRequest: app.JobRequest{ProjectID: m.current.ID, Label: "LDAP audit", Options: []string{"LDAP port=636 request_timeout=8s"}}, Status: "failed", Error: "bind failure " + secret, Started: time.Now(), Ended: time.Now(), Environment: []string{"os=windows arch=amd64"}, Journal: []app.JobEvent{{Time: time.Now(), Message: "LDAP connection attempt"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.store.SaveJob(m.ctx, 8, raw); err != nil {
		t.Fatal(err)
	}
	service, err := app.NewService(m.ctx, m.store, m.cat, m.scanner)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	m.shared = service
	m.syncSharedJobs()
	m.screen, m.jobIndex = "job-details", 0
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m = next.(model)
	paths, err := filepath.Glob(filepath.Join(m.appDir, "reports", "diagnostics-job-8-*.txt"))
	if err != nil || len(paths) != 1 || !strings.Contains(m.message, paths[0]) {
		t.Fatalf("diagnostic export unavailable: %s %v", m.message, err)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, secret) || !strings.Contains(text, "LDAP connection attempt") || !strings.Contains(text, "os=windows") || !strings.Contains(text, "run_id=0") {
		t.Fatal("missing diagnostics or secret leaked")
	}
	info, err := os.Stat(paths[0])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("diagnostic file permissions are not private")
	}
}
