package tui

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wscan/internal/catalog"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/storage"
)

func TestScanFromPortDetailsStaysOnPortAndWritesLog(t *testing.T) {
	var selectedHits, otherHits atomic.Int32
	selected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { selectedHits.Add(1); w.WriteHeader(200) }))
	defer selected.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { otherHits.Add(1); w.WriteHeader(200) }))
	defer other.Close()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "nuclei-templates"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nuclei-templates", "selected.yaml"), []byte("id: selected\ninfo:\n  name: selected\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/'\n    matchers:\n      - type: status\n        status: [200]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, err := store.CreateProject(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	services := []domain.Service{
		{Host: "127.0.0.1", Port: selected.Listener.Addr().(*net.TCPAddr).Port, Protocol: "tcp", Name: "http"},
		{Host: "127.0.0.1", Port: other.Listener.Addr().(*net.TCPAddr).Port, Protocol: "tcp", Name: "http"},
	}
	m := model{ctx: context.Background(), store: store, cat: catalog.NewWithLibrary(dir, dir), scanner: engine.New(store, engine.Config{RPS: 100, Concurrency: 1}), appDir: dir,
		current: domain.Project{ID: id, Name: "test"}, projects: []domain.Project{{ID: id, Name: "test"}},
		hostOrder: []string{"127.0.0.1"}, inventory: map[string]*hostInfo{"127.0.0.1": {services: services}},
		focusCol: 2, hostIndex: 0, serviceIndex: 0, jobEvents: make(chan jobEvent, 16), width: 120, height: 30}
	m.openActionMenu(services)
	if m.actionService == nil || m.actionService.Port != services[0].Port {
		t.Fatal("details column expanded the scan to the whole host")
	}
	m.pendingTemplateIDs = []string{"selected.yaml"}
	spec, message := m.buildSpec(m.actionRows()[0])
	if message != "" || spec.kind != jobPort {
		t.Fatalf("wrong action: %+v %s", spec, message)
	}
	m.startLaunch(spec)
	deadline := time.After(3 * time.Second)
	for m.jobs[0].active() {
		select {
		case ev := <-m.jobEvents:
			m.applyJobEvent(ev)
		case <-deadline:
			m.jobs[0].cancel()
			t.Fatal("job did not finish")
		}
	}
	j := m.jobs[0]
	if selectedHits.Load() != 1 || otherHits.Load() != 0 || j.result == nil || len(j.result.Services) != 1 {
		t.Fatalf("scan escaped selected port: selected=%d other=%d result=%+v", selectedHits.Load(), otherHits.Load(), j.result)
	}
	data, err := os.ReadFile(j.logPath)
	if err != nil || !strings.Contains(string(data), "Только порт") || !strings.Contains(string(data), "selected.yaml") || !strings.Contains(string(data), "Завершено") {
		t.Fatalf("missing launch log: %s, %v", data, err)
	}
	m.screen = "jobs"
	next, _ := m.updateJobs("enter")
	m = next.(model)
	if m.screen != "job-details" || !strings.Contains(m.viewJobDetails(120), "Только порт") {
		t.Fatal("job details do not show port scope")
	}
	next, _ = m.updateJobDetails("enter")
	m = next.(model)
	if m.screen != "desk" || m.focusCol != 1 || m.servicesFor(m.currentHost())[m.serviceIndex].Port != selected.Listener.Addr().(*net.TCPAddr).Port {
		t.Fatal("result did not return to selected port")
	}
}

func TestPortChecksSkipWebTemplatesForSMBService(t *testing.T) {
	entries := []catalog.Entry{
		{Path: "http/exposures/configs/samba-config.yaml", TemplateID: "samba-config", Service: "Web"},
		{Path: "nmap/scripts/smb-protocols.nse", TemplateID: "nmap/smb-protocols", Service: "SMB"},
	}
	ids := []string{"http/exposures/configs/samba-config.yaml", "nmap/scripts/smb-protocols.nse"}
	compatible, skipped := portCompatibleTemplateIDs(entries, domain.Service{Port: 445, Name: "microsoft-ds"}, ids)
	if strings.Join(compatible, ",") != ids[1] || strings.Join(skipped, ",") != ids[0] {
		t.Fatalf("compatible=%v skipped=%v", compatible, skipped)
	}
}

func TestNSEDenialOfServiceScriptsAreSkipped(t *testing.T) {
	if !nseDenialOfServiceScript(nil, "nmap/scripts/smb-flood.nse") {
		t.Fatal("smb-flood must be blocked even when no catalog metadata is loaded")
	}
	entry := catalog.Entry{Path: "nmap/scripts/example.nse", Category: "intrusive, dos"}
	if !nseDenialOfServiceScript([]catalog.Entry{entry}, entry.Path) {
		t.Fatal("NSE DoS category must be blocked")
	}
	if nseDenialOfServiceScript([]catalog.Entry{{Path: "nmap/scripts/smb-protocols.nse", Category: "safe, discovery"}}, "nmap/scripts/smb-protocols.nse") {
		t.Fatal("safe discovery NSE script must remain enabled")
	}
}

func TestNSEIntrusiveScriptsRequireManualOptIn(t *testing.T) {
	unsafe := catalog.Entry{Path: "nmap/scripts/rdp-vuln-check.nse", Impact: catalog.ImpactStrong}
	if !nseRequiresOptInScript([]catalog.Entry{unsafe}, unsafe.Path) {
		t.Fatal("strong-impact NSE scripts must require explicit opt-in")
	}
	safe := catalog.Entry{Path: "nmap/scripts/smb-vuln-ms17-010.nse", Impact: catalog.ImpactActive}
	if nseRequiresOptInScript([]catalog.Entry{safe}, safe.Path) {
		t.Fatal("active check-only NSE scripts must remain available by default")
	}
}
