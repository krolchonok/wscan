package tui

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"wscan/internal/engine"
)

func TestSQLiFormRunPersistsFindingsAndCSV(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/item" {
			id := r.URL.Query().Get("id")
			if strings.Contains(id, "'") {
				w.Write([]byte("You have an error in your SQL syntax near MySQL"))
				return
			}
			w.Write([]byte("item " + id))
			return
		}
		w.Write([]byte(`<html><body><form action="/item" method="get"><input name="id" value="1"></form></body></html>`))
	}))
	defer server.Close()
	m := newTestModelForSettings(t)
	m.appDir = t.TempDir()
	m.current.AllowExploit = true
	m.screen = "sqli-form"
	m.sqliForm.options = engine.SQLiFormOptions{URL: server.URL + "/"}
	got, cmd := m.startSQLiForm()
	m = got.(model)
	batch := cmd().(tea.BatchMsg)
	done := batch[0]().(sqliFormDone)
	if done.err != nil || len(done.result.Hits) != 1 || done.result.Hits[0].Technique != "error-based" {
		t.Fatalf("%+v", done)
	}
	got, _ = m.applySQLiFormDone(done)
	m = got.(model)
	runs, err := m.store.Runs(context.Background(), m.current.ID)
	if err != nil || len(runs) != 1 || runs[0].Status != "completed" {
		t.Fatalf("runs=%v err=%v", runs, err)
	}
	findings, err := m.store.Findings(context.Background(), runs[0].ID)
	if err != nil || len(findings) != 1 || findings[0].TemplateID != "native/sqli-form" {
		t.Fatalf("%v %v", findings, err)
	}
	message := m.exportSQLiForm()
	if !strings.HasPrefix(message, "CSV: ") {
		t.Fatal(message)
	}
	f, err := os.Open(strings.TrimPrefix(message, "CSV: "))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][4] != "error-based" {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
}

func TestSQLiFormRequiresAllowExploit(t *testing.T) {
	m := newTestModelForSettings(t)
	m.appDir = t.TempDir()
	m.screen = "sqli-form"
	m.sqliForm.options = engine.SQLiFormOptions{URL: "http://example.org/"}
	got, cmd := m.startSQLiForm()
	m = got.(model)
	if cmd != nil || m.sqliForm.busy {
		t.Fatalf("expected no-op without AllowExploit: busy=%v cmd=%v", m.sqliForm.busy, cmd)
	}
	if !strings.Contains(m.message, "AllowExploit") {
		t.Fatalf("expected AllowExploit message, got %q", m.message)
	}
}
