package tui

import (
	"context"
	"encoding/csv"
	"errors"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/domain"
	"wscan/internal/ftpclient"
)

func TestFTPMenuAndSelectedNonstandardPort(t *testing.T) {
	service := domain.Service{Host: "127.0.0.1", Port: 2121, Name: "ftp", Protocol: "tcp"}
	m := newTestModelForSettings(t)
	m.screen = "desk"
	m.hostOrder = []string{"127.0.0.1"}
	m.inventory = map[string]*hostInfo{"127.0.0.1": {services: []domain.Service{service}}}
	m.focusCol = 1
	m.openInteractionMenu()
	if m.interactionIndex != 4 || m.ftpBrowser.options.Port != 2121 || m.ftpBrowser.options.Mode != "ftp" {
		t.Fatalf("FTP target=%+v index=%d", m.ftpBrowser.options, m.interactionIndex)
	}
	next, cmd := m.updateInteractionMenu("enter")
	m = next.(model)
	if cmd != nil || m.screen != "ftp-setup" || m.ftpBrowser.busy {
		t.Fatal("opening FTP setup must not send network traffic")
	}
	next, _ = m.updateFTPSetup("s")
	m = next.(model)
	if m.ftpBrowser.options.Port != 2121 || m.ftpBrowser.options.Mode != "explicit" || m.ftpBrowser.options.Insecure {
		t.Fatal("TLS toggle changed nonstandard port or disabled certificate validation")
	}
	if !strings.Contains(m.viewFTPSetup(100), "Anonymous") {
		t.Fatal("anonymous option missing")
	}
	m.screen = "interaction-menu"
	m.interactionIndex = interactionMenuCount - 1
	next, _ = m.updateInteractionMenu("down")
	m = next.(model)
	if m.interactionIndex != 0 {
		t.Fatal("menu does not wrap")
	}
}

func TestFTPNavigationAndCancellationPreserveDirectory(t *testing.T) {
	m := model{ctx: context.Background(), screen: "ftp-browser", ftpBrowser: ftpBrowserState{connected: true, directory: ftpclient.Directory{Path: "/docs/sub", Entries: []ftpclient.Entry{{Name: "file.txt"}}}}}
	next, cmd := m.updateFTPBrowser("left")
	m = next.(model)
	if cmd == nil || !m.ftpBrowser.busy {
		t.Fatal("parent navigation not asynchronous")
	}
	generation := m.ftpBrowser.generation
	m.ftpBrowser.cancel()
	next, _ = m.applyFTPDone(ftpDone{generation: generation, operation: "list", err: errors.New("Access denied")})
	m = next.(model)
	if m.ftpBrowser.directory.Path != "/docs/sub" || len(m.ftpBrowser.directory.Entries) != 1 || !strings.Contains(m.message, "Access denied") {
		t.Fatal("failure lost current directory")
	}
	next, _ = m.updateFTPBrowser("r")
	m = next.(model)
	generation = m.ftpBrowser.generation
	next, _ = m.updateFTPBrowser("esc")
	m = next.(model)
	if m.ftpBrowser.busy || m.ftpBrowser.cancel != nil {
		t.Fatal("cancel did not clear operation")
	}
	next, _ = m.applyFTPDone(ftpDone{generation: generation, operation: "list", directory: ftpclient.Directory{Path: "/late"}})
	m = next.(model)
	if m.ftpBrowser.directory.Path != "/docs/sub" {
		t.Fatal("late result modified canceled browser")
	}
}

func TestFTPUsesPasswordCredentialsAndReturnsFromEditor(t *testing.T) {
	m := newTestModelForSettings(t)
	_, err := m.store.CreateCredential(m.ctx, domain.Credential{ProjectID: m.current.ID, Type: "ntlm-hash", Username: "root", Secret: strings.Repeat("a", 32)})
	if err != nil {
		t.Fatal(err)
	}
	m.ftpBrowser.options = ftpclient.Options{Host: "127.0.0.1", Port: 21, Mode: "ftp"}
	next, _ := m.openFTPSetup()
	m = next.(model)
	m.ftpBrowser.credIndex = 1
	next, cmd := m.updateFTPSetup("enter")
	m = next.(model)
	if cmd != nil || m.ftpBrowser.busy || !strings.Contains(m.message, "паролем") {
		t.Fatal("FTP accepted NTLM hash")
	}
	m.openCredentials()
	if m.credentialsReturn != "ftp-setup" {
		t.Fatal("return screen lost")
	}
	next, _ = m.updateCredentials("esc")
	m = next.(model)
	if m.screen != "ftp-setup" {
		t.Fatal("editor did not return to FTP")
	}
}

func TestFTPPortInputAndCSV(t *testing.T) {
	m := model{screen: "ftp-setup", ftpBrowser: ftpBrowserState{options: ftpclient.Options{Port: 21}}}
	next, _ := m.updateFTPSetup("p")
	m = next.(model)
	m.input = "2121"
	if !strings.Contains(m.viewInput(100), "FTP") {
		t.Fatal("port input has no label")
	}
	next, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if m.screen != "ftp-setup" || m.ftpBrowser.options.Port != 2121 {
		t.Fatal("FTP port input failed")
	}
	file, err := exportFTPEntries(t.TempDir(), "server", ftpclient.Directory{Path: "/docs", Entries: []ftpclient.Entry{{Name: "report,2026.txt", Size: 42}}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1][1] != "/docs/report,2026.txt" || rows[1][2] != "report,2026.txt" {
		t.Fatalf("rows=%v", rows)
	}
}
