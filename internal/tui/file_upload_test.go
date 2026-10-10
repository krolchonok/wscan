package tui

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"wscan/internal/engine"
)

func TestFileUploadRunPersistsFindingsAndCSV(t *testing.T) {
	var mu sync.Mutex
	stored := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/upload.php" && r.Method == http.MethodPost:
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				w.WriteHeader(400)
				return
			}
			file, header, err := r.FormFile("file")
			if err != nil {
				w.WriteHeader(400)
				return
			}
			defer file.Close()
			if strings.HasSuffix(header.Filename, ".php") {
				w.WriteHeader(400)
				return
			}
			data := make([]byte, 0, 256)
			buf := make([]byte, 256)
			for {
				n, rerr := file.Read(buf)
				if n > 0 {
					data = append(data, buf[:n]...)
				}
				if rerr != nil {
					break
				}
			}
			mu.Lock()
			stored[header.Filename] = string(data)
			mu.Unlock()
			w.Write([]byte("ok: uploads/" + header.Filename))
		case strings.HasPrefix(r.URL.Path, "/uploads/"):
			name := strings.TrimPrefix(r.URL.Path, "/uploads/")
			mu.Lock()
			content, ok := stored[name]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			start := strings.Index(content, `echo "`)
			if start >= 0 && strings.HasSuffix(name, ".phtml") {
				start += len(`echo "`)
				end := strings.Index(content[start:], `"`)
				w.Write([]byte(content[start : start+end]))
				return
			}
			w.Write([]byte(content))
		default:
			w.Write([]byte(`<html><body><form action="/upload.php" method="post" enctype="multipart/form-data"><input type="file" name="file"></form></body></html>`))
		}
	}))
	defer server.Close()
	m := newTestModelForSettings(t)
	m.appDir = t.TempDir()
	m.current.AllowExploit = true
	m.screen = "file-upload"
	m.fileUpload.options = engine.FileUploadOptions{URL: server.URL + "/"}
	got, cmd := m.startFileUpload()
	m = got.(model)
	batch := cmd().(tea.BatchMsg)
	done := batch[0]().(fileUploadDone)
	if done.err != nil || len(done.result.Hits) != 1 {
		t.Fatalf("%+v", done)
	}
	got, _ = m.applyFileUploadDone(done)
	m = got.(model)
	runs, err := m.store.Runs(context.Background(), m.current.ID)
	if err != nil || len(runs) != 1 || runs[0].Status != "completed" {
		t.Fatalf("runs=%v err=%v", runs, err)
	}
	findings, err := m.store.Findings(context.Background(), runs[0].ID)
	if err != nil || len(findings) != 1 || findings[0].TemplateID != "native/file-upload-rce" || findings[0].Severity != "critical" {
		t.Fatalf("%v %v", findings, err)
	}
	message := m.exportFileUpload()
	if !strings.HasPrefix(message, "CSV: ") {
		t.Fatal(message)
	}
	f, err := os.Open(strings.TrimPrefix(message, "CSV: "))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
}

func TestFileUploadRequiresAllowExploit(t *testing.T) {
	m := newTestModelForSettings(t)
	m.appDir = t.TempDir()
	m.screen = "file-upload"
	m.fileUpload.options = engine.FileUploadOptions{URL: "http://example.org/"}
	got, cmd := m.startFileUpload()
	m = got.(model)
	if cmd != nil || m.fileUpload.busy {
		t.Fatalf("expected no-op without AllowExploit: busy=%v cmd=%v", m.fileUpload.busy, cmd)
	}
	if !strings.Contains(m.message, "AllowExploit") {
		t.Fatalf("expected AllowExploit message, got %q", m.message)
	}
}
