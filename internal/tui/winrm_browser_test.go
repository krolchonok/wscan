package tui

import (
	"context"
	"encoding/csv"
	"os"
	"strings"
	"testing"

	"wscan/internal/domain"
	"wscan/internal/engine/js"
)

func TestInteractionMenuCanOpenWinRM(t *testing.T) {
	m := model{screen: "interaction-menu", interactionIndex: 1, winrmBrowser: winRMBrowserState{options: js.WinRMOptions{Host: "127.0.0.1", Port: 5986, HTTPS: true}}}
	text := m.viewInteractionMenu(120)
	if !strings.Contains(text, "SMB") || !strings.Contains(text, "WinRM") {
		t.Fatal(text)
	}
	next, _ := m.updateInteractionMenu("up")
	m = next.(model)
	if m.interactionIndex != 0 {
		t.Fatal("menu navigation failed")
	}
}

func TestWinRMStateCancellationAndStaleResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := model{screen: "winrm-browser", winrmBrowser: winRMBrowserState{generation: 1, busy: true, cancel: cancel, connected: true, directory: js.WinRMDirectory{Path: `C:\Users`}}}
	next, _ := m.updateWinRMBrowser("esc")
	m = next.(model)
	if ctx.Err() == nil || m.winrmBrowser.busy {
		t.Fatal("operation was not canceled")
	}
	next, _ = m.applyWinRMDone(winRMDone{generation: 1, operation: "list", directory: js.WinRMDirectory{Path: `C:\wrong`}})
	m = next.(model)
	if m.winrmBrowser.directory.Path != `C:\Users` {
		t.Fatal("stale directory replaced current state")
	}
}

func TestWinRMSetupRejectsHashAndDisconnectClearsCredential(t *testing.T) {
	m := model{screen: "winrm-setup", winrmBrowser: winRMBrowserState{credentials: []domain.Credential{{Type: "ntlm-hash", Username: "user", Secret: "secret"}}}}
	next, cmd := m.updateWinRMSetup("enter")
	m = next.(model)
	if cmd != nil || !strings.Contains(m.message, "NTLM") {
		t.Fatal("hash used as a password")
	}
	m.screen = "winrm-browser"
	m.winrmBrowser.connected = true
	m.winrmBrowser.options.Credential = domain.Credential{Secret: "password"}
	next, _ = m.updateWinRMBrowser("esc")
	m = next.(model)
	if m.winrmBrowser.connected || m.winrmBrowser.options.Credential.Secret != "" {
		t.Fatal("disconnected state retained password")
	}
}

func TestWinRMCSVAndTerminalText(t *testing.T) {
	listing := js.WinRMDirectory{Path: `C:\Users`, Entries: []js.WinRMFile{{Name: "a,b.txt", Path: `C:\Users\a,b.txt`, Owner: `CORP\user`, Rights: "Read [Allow]"}}}
	path, err := exportWinRMDirectory(t.TempDir(), "host", listing)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	rows, err := csv.NewReader(file).ReadAll()
	if err != nil || rows[1][2] != "a,b.txt" || rows[1][6] != `CORP\user` || rows[1][7] != "Read [Allow]" {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if strings.ContainsRune(sanitizeWinRMText("hello\x1b[2J\r\nworld"), '\x1b') {
		t.Fatal("remote output can control terminal")
	}
	m := model{winrmBrowser: winRMBrowserState{options: js.WinRMOptions{Credential: domain.Credential{Username: "user", Secret: "secret-password"}}, directory: listing}}
	if strings.Contains(m.viewWinRMBrowser(120), "secret-password") {
		t.Fatal("password displayed")
	}
}

func TestWinRMOffersCommandAndPersistentShell(t *testing.T) {
	m := model{screen: "winrm-browser", winrmBrowser: winRMBrowserState{connected: true, directory: js.WinRMDirectory{Path: `C:\Users`}}}
	next, _ := m.updateWinRMBrowser("c")
	m = next.(model)
	if m.screen != "input" || m.inputAction != "winrm-command" {
		t.Fatal("one-command input is unavailable")
	}
	m.screen = "winrm-shell"
	next, _ = m.updateWinRMShell("enter")
	m = next.(model)
	if m.screen != "input" || m.inputAction != "winrm-shell-command" {
		t.Fatal("shell command input is unavailable")
	}
}

func TestWinRMACLVisibleAtRightWithLongNames(t *testing.T) {
	m := model{height: 24, winrmBrowser: winRMBrowserState{directory: js.WinRMDirectory{Entries: []js.WinRMFile{{Name: strings.Repeat("longname", 20), Rights: `CORP\administrator: FullControl [Allow]`, Modified: "2026-10-05 16:00:00"}}}}}
	text := m.viewWinRMBrowser(80)
	if !strings.Contains(text, "FullControl") {
		t.Fatal("permissions were clipped by a long file name")
	}
}
