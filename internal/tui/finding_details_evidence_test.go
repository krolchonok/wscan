package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
)

func TestFindingEvidenceTextHidesMatcherExpressionByDefault(t *testing.T) {
	got := findingEvidenceText(`dsl matched: success == true && contains(response, "IPC$"); json: ADMIN$, C$, IPC$; user=" " pass=" "`, false)
	want := `Данные JSON: ADMIN$, C$, IPC$; user=" " pass=" "`
	if got != want {
		t.Fatalf("findingEvidenceText() = %q, want %q", got, want)
	}
}

func TestFindingEvidenceTextShowsMatcherExpressionInRawMode(t *testing.T) {
	evidence := `dsl matched: success == true && contains(response, "IPC$"); json: ADMIN$, C$, IPC$`
	if got := findingEvidenceText(evidence, true); got != evidence {
		t.Fatalf("raw findingEvidenceText() = %q, want unchanged evidence %q", got, evidence)
	}
}

func TestFindingEvidenceTextExplainsMatchWithoutExtractedData(t *testing.T) {
	if got := findingEvidenceText(`dsl matched: status_code == 200`, false); got != "Шаблон подтвердил условие совпадения." {
		t.Fatalf("findingEvidenceText() = %q", got)
	}
}

func TestFindingEvidenceTextPrettyPrintsJSONExtractor(t *testing.T) {
	got := findingEvidenceText(`json: [{"Name":"Public","Read":true,"Write":false}]`, false)
	want := "Данные JSON:\n[\n  {\n    \"Name\": \"Public\",\n    \"Read\": true,\n    \"Write\": false\n  }\n]"
	if got != want {
		t.Fatalf("findingEvidenceText() = %q, want %q", got, want)
	}
}

func TestFindingDetailsUsesJSONResponseWhenEvidenceIsEmpty(t *testing.T) {
	f := domain.Finding{
		Name:     "SMB anonymous shares",
		Severity: "info",
		Response: `[{"Name":"Public","Read":true,"Write":false}]`,
		Time:     time.Now(),
	}
	m := model{findingDetail: &f}
	got := strings.Join(m.findingLines(120), "\n")
	for _, want := range []string{"Public", "Чтение", "Запись", "да", "нет"} {
		if !strings.Contains(got, want) {
			t.Fatalf("finding details do not include parsed JSON field %q: %s", want, got)
		}
	}
}

func TestLongInformationalFindingTitleRemainsVisible(t *testing.T) {
	const title = "SSH Password-based Authentication"
	f := domain.Finding{Name: title, Severity: "info", Time: time.Now()}
	if got := resultLabel(f); got != title {
		t.Fatalf("list label = %q, want full title %q", got, title)
	}
	leftWidth, _ := findingPanelWidths(120)
	row := ansi.Strip(renderListRow(resultLabel(f), true, leftWidth))
	if !strings.Contains(row, title) {
		t.Fatalf("finding list row clips title at terminal width 120: %q", row)
	}

	m := model{findingDetail: &f}
	lines := strings.Join(m.findingLines(24), " ")
	if !strings.Contains(strings.Join(strings.Fields(lines), " "), title) {
		t.Fatalf("details do not retain full title: %q", lines)
	}
}
