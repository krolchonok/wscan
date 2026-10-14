package tui

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"wscan/internal/adscan"
	"wscan/internal/app"
)

func TestADChecksSeparateAnonymousAndCredentialedActions(t *testing.T) {
	m := newTestModelForSettings(t)
	m.width, m.height = 160, 50
	view := ansi.Strip(m.viewADAccess(160))
	anon := strings.Index(view, "Без учётки (анонимно)")
	auth := strings.Index(view, "Нужна учётка / билет")
	if anon < 0 || auth <= anon {
		t.Fatal(view)
	}
	for _, name := range []string{"DNS:", "AS-REP", "LDAP RootDSE", "SYSVOL / NETLOGON"} {
		if !strings.Contains(view[anon:auth], name) {
			t.Fatalf("anonymous action %q missing", name)
		}
	}
	m.adAccessHost, m.adAccessDomain, m.adAccessCred = "192.0.2.1", "lab.example", -1
	for i, action := range adAccessModes {
		if i < 2 || anonymousADMode(action.id) || action.id == "kerberoast" {
			continue
		}
		m.adAccessIndex = i
		next, _ := m.startADAccess()
		got := next.(model)
		if len(got.jobs) != 0 || !strings.Contains(got.message, "учётку") {
			t.Fatalf("%s started without credentials: %s", action.id, got.message)
		}
	}
	indices := adCheckIndices()
	for i := 1; i < len(indices); i++ {
		if nextADCheck(indices[i-1], 1) != indices[i] || nextADCheck(indices[i], -1) != indices[i-1] {
			t.Fatal("navigation does not follow displayed groups")
		}
	}
	m.height = 24
	m.screen = "ad-access"
	for i, action := range adAccessModes {
		if i < 2 {
			continue
		}
		m.adAccessIndex = i
		view := ansi.Strip(m.viewADAccess(160))
		if !strings.Contains(view, action.name) {
			t.Fatalf("selected check hidden in short terminal: %s", action.id)
		}
	}
}

func TestDNSAccessReportsEachFailedStep(t *testing.T) {
	m := newTestModelForSettings(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close() // Server closes instead of answering either DNS request.
		}
	}()
	var journal []string
	result, err := m.runADAccess(adscan.AccessOptions{Mode: "dns", Host: "127.0.0.1", Domain: "lab.example", DNSPort: l.Addr().(*net.TCPAddr).Port, ExportDir: t.TempDir(), Timeout: time.Second})(context.Background(), func(s string, _ ...int) {
		journal = append(journal, s)
	})
	if err != nil || len(result.Errors) != 2 {
		t.Fatalf("DNS failures lost: %v %v", result.Errors, err)
	}
	for _, want := range []string{"DNS AXFR", "DNS recursion capability", "[error]"} {
		if !strings.Contains(strings.Join(journal, "\n"), want) {
			t.Fatalf("missing DNS diagnostic %q: %v", want, journal)
		}
	}
}

func TestRestoredFailedADJobShowsCauseInSummaryAndJournal(t *testing.T) {
	m := newTestModelForSettings(t)
	cause := "ldaps://192.0.2.1:636 · NTLM bind: connection reset by peer"
	raw, err := json.Marshal(app.Job{ID: 5, JobRequest: app.JobRequest{ProjectID: m.current.ID, Kind: "ad-access", Label: "LDAP audit"}, Status: "failed", Stage: "Ошибка", Error: cause, RunID: 42, Started: time.Now(), Ended: time.Now(), Journal: []app.JobEvent{{Time: time.Now(), Message: "Ошибка"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.store.SaveJob(m.ctx, 5, raw); err != nil {
		t.Fatal(err)
	}
	service, err := app.NewService(m.ctx, m.store, m.cat, m.scanner)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	m.shared = service
	m.syncSharedJobs()
	j := m.jobByID(5)
	if j == nil || !strings.Contains(strings.Join(j.journal, "\n"), cause) {
		t.Fatal("legacy journal hides execution error")
	}
	m.height, m.width = 40, 140
	view := ansi.Strip(m.viewJobSummary(140, j))
	if !strings.Contains(view, cause) || strings.Contains(view, "… ошибка Ошибка") {
		t.Fatal(view)
	}
}
