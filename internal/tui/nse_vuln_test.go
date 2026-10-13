package tui

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wscan/internal/catalog"
	"wscan/internal/domain"
	"wscan/internal/storage"
)

func vulnLibrary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"nmap/scripts", "nuclei-templates"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	entries := map[string]any{}
	for name, cats := range map[string][]string{"selected": {"vuln"}, "dos": {"vuln", "dos"}, "strong": {"vuln", "intrusive"}, "wrong": {"discovery"}, "filename-vuln": {"safe"}, "broken": {"vuln"}} {
		path := "nmap/scripts/" + name + ".nse"
		entries[path] = map[string]any{"kind": "nse", "path": path, "service": "SSH", "nse_categories": cats}
		// The synthetic action returns local data and never opens a socket.
		source := `portrule = function(host, port) return port.number == 22 end
 action = function(host, port) return "local fixture only" end`
		if name == "broken" {
			source = `action = function() return nil end`
		}
		if err := os.WriteFile(filepath.Join(dir, path), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	entries["http/cve.yaml"] = map[string]any{"kind": "nuclei", "nse_categories": []string{"vuln"}}
	b, _ := json.Marshal(map[string]any{"version": 1, "entries": entries})
	if err := os.WriteFile(filepath.Join(dir, "categories.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}
func TestNSEVulnSelectionAndRestrictions(t *testing.T) {
	dir := vulnLibrary(t)
	m := model{cat: catalog.NewWithLibrary(dir, dir)}
	ids, skipped, e := m.localVulnScripts(context.Background())
	if e != nil || len(ids) != 1 || ids[0] != "nmap/scripts/selected.nse" || len(skipped) != 3 {
		t.Fatalf("%v %v %v", ids, skipped, e)
	}
	m.current.AllowExploit = true
	ids, skipped, e = m.localVulnScripts(context.Background())
	if e != nil || len(ids) != 2 || len(skipped) != 2 {
		t.Fatalf("%v %v %v", ids, skipped, e)
	}
	for _, id := range ids {
		if strings.Contains(id, "dos") {
			t.Fatal("DoS must remain excluded")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e = m.localVulnScripts(ctx); e == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestNSEVulnButtonAndPersistedResults(t *testing.T) {
	dir := vulnLibrary(t)
	store, e := storage.Open(filepath.Join(dir, "test.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	ctx := context.Background()
	id, e := store.CreateProject(ctx, "vuln")
	if e != nil {
		t.Fatal(e)
	}
	a := domain.Service{Host: "192.0.2.1", Port: 22, Protocol: "tcp", Name: "ssh"}
	b := domain.Service{Host: "192.0.2.2", Port: 22, Protocol: "tcp", Name: "ssh"}
	m := model{ctx: ctx, current: domain.Project{ID: id, TimeoutSeconds: 1, RPS: 10, Concurrency: 1}, store: store, cat: catalog.NewWithLibrary(dir, dir), checkMenuIndex: 2, jobEvents: make(chan jobEvent, 32), inventory: map[string]*hostInfo{a.Host: {services: []domain.Service{a}}, b.Host: {services: []domain.Service{b}}}, width: 110, height: 24}
	if !strings.Contains(m.viewChecksMenu(100), "NSE vuln") {
		t.Fatal("selected active action not visible")
	}
	got, _ := m.updateChecksMenu("enter")
	m = got.(model)
	if m.screen != "jobs" || len(m.jobs) != 1 || m.jobs[0].kind != "nse-vuln" {
		t.Fatal("active button did not launch its own job")
	}
	var ev jobEvent
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev = <-m.jobEvents:
		case <-deadline:
			t.Fatal("job did not complete")
		}
		if ev.done {
			break
		}
	}
	if ev.err != nil || len(ev.result.Services) != 2 || len(ev.result.Findings) != 2 || len(ev.result.Skipped) != 3 {
		t.Fatalf("%+v", ev)
	}
	for _, f := range ev.result.Findings {
		if f.TemplateID != "nmap/selected" || f.Risk != "active" {
			t.Fatal(f)
		}
	}
	fs, e := store.Findings(ctx, ev.result.RunID)
	if e != nil || len(fs) != 2 {
		t.Fatalf("%v %v", fs, e)
	}
}
func TestNSEVulnNoServicesGuard(t *testing.T) {
	m := model{checkMenuIndex: 2}
	got, _ := m.updateChecksMenu("enter")
	m = got.(model)
	if len(m.jobs) != 0 || !strings.Contains(m.message, "Нет сохранённых сервисов") {
		t.Fatal("empty inventory started active job")
	}
}
