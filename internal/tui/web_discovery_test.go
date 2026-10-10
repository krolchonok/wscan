package tui

import (
	"context"
	"encoding/csv"
	tea "github.com/charmbracelet/bubbletea"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"wscan/internal/engine"
)

func TestWebDiscoveryRunPersistsFindingsAndCSV(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Write([]byte("admin"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	m := newTestModelForSettings(t)
	m.appDir = t.TempDir()
	words := filepath.Join(m.appDir, "words.txt")
	if err := os.WriteFile(words, []byte("admin\nmissing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m.screen = "web-discovery"
	m.webDiscovery.options = engine.WebDiscoveryOptions{URL: server.URL, Wordlist: words, RPS: 10000, FilterWildcard: true}
	got, cmd := m.startWebDiscovery()
	m = got.(model)
	batch := cmd().(tea.BatchMsg)
	done := batch[0]().(webDiscoveryDone)
	if done.err != nil || len(done.result.Hits) != 1 {
		t.Fatalf("%+v", done)
	}
	got, _ = m.applyWebDiscoveryDone(done)
	m = got.(model)
	runs, err := m.store.Runs(context.Background(), m.current.ID)
	if err != nil || len(runs) != 1 || runs[0].Status != "completed" {
		t.Fatalf("runs=%v err=%v", runs, err)
	}
	findings, err := m.store.Findings(context.Background(), runs[0].ID)
	if err != nil || len(findings) != 1 || findings[0].TemplateID != "native/web-discovery" {
		t.Fatalf("%v %v", findings, err)
	}
	message := m.exportWebDiscovery()
	if !strings.HasPrefix(message, "CSV: ") {
		t.Fatal(message)
	}
	f, err := os.Open(strings.TrimPrefix(message, "CSV: "))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][1] != "200" {
		t.Fatalf("%v %v", rows, err)
	}
}
func TestWebDiscoveryStaleProgressAndCancellation(t *testing.T) {
	cancelled := false
	m := model{webDiscovery: webDiscoveryState{busy: true, generation: 2, cancel: func() { cancelled = true }}}
	ch := make(chan webDiscoveryEvent)
	got, _ := m.applyWebDiscoveryEvent(webDiscoveryEvent{generation: 1, progress: engine.WebDiscoveryProgress{Done: 100}}, ch)
	m = got.(model)
	if m.webDiscovery.done != 0 {
		t.Fatal("stale progress applied")
	}
	got, _ = m.updateWebDiscovery("esc")
	if !cancelled || !got.(model).webDiscovery.busy {
		t.Fatal("cancel request should await completion")
	}
	got, _ = m.applyWebDiscoveryDone(webDiscoveryDone{generation: 1})
	if !got.(model).webDiscovery.busy {
		t.Fatal("stale completion applied")
	}
}
