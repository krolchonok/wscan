package tui

import (
	"context"
	"encoding/csv"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"wscan/internal/domain"
	"wscan/internal/engine/js"
)

func TestInteractionEntryOpensWithoutScanPicker(t *testing.T) {
	service := domain.Service{Host: "127.0.0.1", Port: 445, Name: "microsoft-ds", Protocol: "tcp"}
	m := model{ctx: context.Background(), screen: "desk", hostOrder: []string{"127.0.0.1"}, inventory: map[string]*hostInfo{"127.0.0.1": {services: []domain.Service{service}}}, focusCol: 1}
	m.openActionMenu([]domain.Service{service})
	if m.screen != "action-menu" {
		t.Fatalf("port bypasses action menu: %s", m.screen)
	}
	m.actionIndex = 1
	next, cmd := m.updateActionMenu("enter")
	m = next.(model)
	if cmd != nil || m.screen != "interaction-menu" || m.smbBrowser.port != 445 {
		t.Fatalf("interaction unexpectedly scans: %+v", m.smbBrowser)
	}
	next, cmd = m.updateInteractionMenu("enter")
	m = next.(model)
	if m.screen != "smb-browser" || cmd == nil || !m.smbBrowser.busy {
		t.Fatal("SMB browser did not request an asynchronous share listing")
	}
	m.smbBrowser.cancel()
}

func TestSMBBrowserNavigationAndFailedDirectoryKeepsLocation(t *testing.T) {
	m := model{ctx: context.Background(), screen: "smb-browser", smbBrowser: smbBrowserState{host: "127.0.0.1", port: 445, share: "Public", directory: "folder/sub", entries: []js.SMBEntry{{Name: "file.txt"}}}}
	next, cmd := m.updateSMBBrowser("left")
	m = next.(model)
	if cmd == nil || !m.smbBrowser.busy {
		t.Fatal("parent navigation did not load directory")
	}
	m.smbBrowser.cancel()
	next, _ = m.applySMBBrowserDone(smbBrowserDone{generation: m.smbBrowser.generation, operation: "list", share: "Public", directory: "folder", err: errors.New("access denied")})
	m = next.(model)
	if m.smbBrowser.directory != "folder/sub" || len(m.smbBrowser.entries) != 1 || !strings.Contains(m.message, "access denied") {
		t.Fatal("failed navigation lost current location")
	}
	next, _ = m.applySMBBrowserDone(smbBrowserDone{generation: m.smbBrowser.generation, operation: "list", share: "Public", directory: "folder", entries: []js.SMBEntry{{Name: "sub", Directory: true}}})
	m = next.(model)
	if m.smbBrowser.directory != "folder" || !m.smbBrowser.entries[0].Directory {
		t.Fatal("successful parent navigation not committed")
	}
}

func TestSMBBrowserCancellationIgnoresLateResults(t *testing.T) {
	m := model{ctx: context.Background(), screen: "smb-browser"}
	m, ctx := m.beginSMBOperation()
	generation := m.smbBrowser.generation
	next, _ := m.updateSMBBrowser("esc")
	m = next.(model)
	if ctx.Err() != context.Canceled || m.smbBrowser.busy {
		t.Fatal("operation was not canceled")
	}
	next, _ = m.applySMBBrowserDone(smbBrowserDone{generation: generation, operation: "list", share: "late", entries: []js.SMBEntry{{Name: "late"}}})
	m = next.(model)
	if m.smbBrowser.share != "" || len(m.smbBrowser.entries) != 0 {
		t.Fatal("late result changed browser state")
	}
}

func TestSMBPreviewAndCSVPreserveFileData(t *testing.T) {
	if got := smbPreview([]byte("hello\n\x1b[2Jworld"), 100000); !strings.Contains(got, "hello\n") || strings.ContainsRune(got, '\x1b') || !strings.Contains(got, "Предпросмотр") {
		t.Fatalf("unsafe or incomplete text preview: %q", got)
	}
	if got := smbPreview([]byte{0, 1, 255}, 3); !strings.Contains(got, "Двоичный файл") || !strings.Contains(got, "00 01 ff") {
		t.Fatalf("binary preview: %q", got)
	}
	modified := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	name := "report,2026.txt"
	filename, err := exportSMBEntries(t.TempDir(), "server", "Public", "docs", []js.SMBEntry{{Name: name, Size: 42, Modified: modified}})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1][3] != name || records[1][2] != "docs/"+name || records[1][5] != "42" {
		t.Fatalf("CSV lost metadata: %v", records)
	}
}

func TestSMBShareRightsLabels(t *testing.T) {
	yes, no := true, false
	for _, test := range []struct {
		entry js.SMBEntry
		want  string
	}{
		{js.SMBEntry{Read: &yes, Write: &yes}, "READ, WRITE"},
		{js.SMBEntry{Read: &yes, Write: &no}, "READ"},
		{js.SMBEntry{Read: &no, Write: &no}, "нет доступа"},
		{js.SMBEntry{Read: &yes}, "READ, WRITE ?"},
		{js.SMBEntry{Name: "IPC$"}, "RPC (служебная)"},
	} {
		if got := smbRightsLabel(test.entry); got != test.want {
			t.Fatalf("rights=%q want %q", got, test.want)
		}
	}
}

func TestSMBShareRightsRemainVisibleWithLongName(t *testing.T) {
	yes, no := true, false
	m := model{screen: "smb-browser", width: 80, height: 24, smbBrowser: smbBrowserState{entries: []js.SMBEntry{{Name: strings.Repeat("LongShare", 12), Read: &yes, Write: &no}}}}
	got := m.viewSMBBrowser(80)
	if !strings.Contains(got, "READ") || !strings.Contains(got, "Права доступа") {
		t.Fatalf("rights column is clipped: %s", got)
	}
}

func TestSMBDownloadProgressAndCancellation(t *testing.T) {
	p := &smbDownloadProgress{name: "archive.zip", total: 2048, started: time.Now().Add(-time.Second)}
	p.written.Store(1024)
	m := model{screen: "smb-browser", width: 140, height: 30, smbBrowser: smbBrowserState{busy: true, generation: 7, download: p}}
	view := m.viewSMBBrowser(140)
	for _, want := range []string{"archive.zip", "50.0%", "1.0 КиБ / 2.0 КиБ"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %q in %s", want, view)
		}
	}
	_, cmd := m.applySMBDownloadTick(smbDownloadTick{generation: 7})
	if cmd == nil {
		t.Fatal("active transfer stopped refreshing")
	}
	_, cmd = m.applySMBDownloadTick(smbDownloadTick{generation: 6})
	if cmd != nil {
		t.Fatal("stale transfer kept refreshing")
	}
	canceled := false
	m.smbBrowser.cancel = func() { canceled = true }
	next, _ := m.updateSMBBrowser("esc")
	m = next.(model)
	if !canceled || m.smbBrowser.busy {
		t.Fatal("transfer not canceled")
	}
	_, cmd = m.applySMBDownloadTick(smbDownloadTick{generation: 7})
	if cmd != nil {
		t.Fatal("canceled transfer kept refreshing")
	}
	next, _ = m.applySMBBrowserDone(smbBrowserDone{generation: 7, operation: "download", text: "late.zip"})
	if next.(model).message != "Операция отменена" {
		t.Fatal("late completion overwrote cancellation")
	}
}
