package tui

import (
	"strings"
	"testing"

	"wscan/internal/domain"
)

func TestSavedSMBExtractorRendersSharesAndCredentials(t *testing.T) {
	evidence := `dsl: [
 {"Name":"ADMIN$","Read":false,"Write":false},
 {"Name":"backups","Read":true,"Write":false},
 {"Name":"C$","Read":false,"Write":false},
 {"Name":"IPC$","Read":false,"Write":false}
 ]; user=" " pass=" "`
	f := domain.Finding{TemplateID: "smb-default-login", Evidence: evidence}
	table, ok := smbFindingTable(f, 50)
	if !ok {
		t.Fatal("saved wrapped JSON was not parsed")
	}
	for _, want := range []string{"Шара", "Чтение", "Запись", "ADMIN$", "backups", "C$", "IPC$", "служебная (RPC)", "Пользователь:", "Пароль:", "1 пробел"} {
		if !strings.Contains(table, want) {
			t.Fatalf("missing %q: %s", want, table)
		}
	}
	for _, line := range strings.Split(table, "\n") {
		if strings.HasPrefix(line, "backups") && !strings.Contains(line, "да       нет") {
			t.Fatalf("wrong access flags: %s", line)
		}
	}
	m := model{findingDetail: &f}
	text := strings.Join(m.findingLines(50), "\n")
	if strings.Contains(text, "dsl:") || strings.Contains(text, `"Read"`) || strings.Contains(text, "user=") {
		t.Fatalf("raw JSON leaked into normal details: %s", text)
	}
	m.findingRaw = true
	raw := strings.Join(m.findingLines(200), "\n")
	if !strings.Contains(raw, `"Read":true`) || !strings.Contains(raw, `user=" " pass=" "`) {
		t.Fatal("raw evidence was lost")
	}
}

func TestSMBTableUsesFullResponseWhenEvidenceWasTruncated(t *testing.T) {
	f := domain.Finding{Evidence: `dsl: [{"Name":"first","Read":true…`, Response: `[{"name":"first","read":true,"write":false},{"name":"last","read":false,"write":true}]`}
	table, ok := smbFindingTable(f, 50)
	if !ok || !strings.Contains(table, "last") {
		t.Fatalf("full response was not used: %s", table)
	}
}

func TestSMBShareParserDoesNotInventPermissions(t *testing.T) {
	for _, value := range []string{`[{"Name":"unrelated"}]`, `[{"Name":"bad","Read":"true"}]`, `[]`, `dsl: [{"Name":"broken","Read":true…`} {
		if _, ok := parseSMBFindingShares(value); ok {
			t.Fatalf("accepted invalid share evidence: %s", value)
		}
	}
	f := domain.Finding{Response: `[{"Name":"read-only","Read":true},{"Name":"denied","Read":false,"Write":false}]`}
	table, ok := smbFindingTable(f, 50)
	if !ok || !strings.Contains(table, "?") {
		t.Fatalf("missing permission became a denial: %s", table)
	}
}

func TestSMBTableKeepsLongShareNamesAndParsesBracketsInNames(t *testing.T) {
	name := strings.Repeat("long", 15) + "[archive]"
	f := domain.Finding{Response: `[{"Name":"` + name + `","Read":true,"Write":true}]`}
	table, ok := smbFindingTable(f, 30)
	if !ok || !strings.Contains(table, name) || !strings.Contains(table, "да       да") {
		t.Fatalf("table lost share name or permissions: %s", table)
	}
}
