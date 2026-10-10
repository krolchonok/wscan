package tui

import (
	"github.com/charmbracelet/x/ansi"
	"strings"
	"testing"
)

func TestSQLDataTableEqualColumnsAndUnicodeWrapping(t *testing.T) {
	result := browserTestResult([]string{"id", "имя", "description"}, [][]any{{1, "Анна", "оченьдлинноезначениебезпробелов"}, {2, "界界", nil}})
	text := sqlDataTable(result, 46, 0)
	tableWidth := 0
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "│") && !strings.HasPrefix(line, "┌") && !strings.HasPrefix(line, "├") && !strings.HasPrefix(line, "└") {
			continue
		}
		w := ansi.StringWidth(line)
		if tableWidth == 0 {
			tableWidth = w
		}
		if w != tableWidth || w > 46 {
			t.Fatalf("uneven width %d expected %d: %q", w, tableWidth, line)
		}
		if strings.HasPrefix(line, "│") {
			cells := strings.Split(line, "│")
			for _, cell := range cells[1 : len(cells)-1] {
				if ansi.StringWidth(cell) != 14 {
					t.Fatalf("uneven cell: %q", cell)
				}
			}
		}
	}
	if !strings.Contains(text, "NULL") || !strings.Contains(text, "Анна") || !strings.Contains(text, "界界") {
		t.Fatal(text)
	}
}
func TestSQLDataTableColumnWindowAndMultiline(t *testing.T) {
	result := browserTestResult([]string{"one", "two", "three", "four"}, [][]any{{"first", "second", "line1\nline2", "last"}})
	text := sqlDataTable(result, 23, 2)
	if !strings.Contains(text, "three") || !strings.Contains(text, "four") || strings.Contains(text, "second") || !strings.Contains(text, "line2") || !strings.Contains(text, "столбцы 3–4 из 4") {
		t.Fatal(text)
	}
}
