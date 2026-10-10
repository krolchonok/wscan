package tui

import (
	"fmt"
	"github.com/charmbracelet/x/ansi"
	"strings"
)

// sqlDataTable gives every visible column the same terminal-cell width.
// Wide tables expose a window of columns instead of squeezing cells to nothing.
func sqlDataTable(result map[string]any, width, start int) string {
	cols, data, truncated := sqlBrowserRows(result)
	if len(cols) == 0 {
		return "Нет столбцов"
	}
	width = max(5, width)
	visible := min(len(cols), max(1, (width-1)/11))
	start = min(max(0, start), max(0, len(cols)-visible))
	end := min(len(cols), start+visible)
	cellWidth := max(1, (width-1)/visible-3)
	rule := func(left, middle, right string) string {
		parts := make([]string, visible)
		for i := range parts {
			parts[i] = strings.Repeat("─", cellWidth+2)
		}
		return left + strings.Join(parts, middle) + right + "\n"
	}
	var out strings.Builder
	row := func(values []string) {
		cells := make([][]string, visible)
		height := 1
		for i := range cells {
			value := ""
			if i < len(values) {
				value = values[i]
			}
			value = strings.ReplaceAll(sanitizeWinRMText(value), "\t", "    ")
			cells[i] = strings.Split(ansi.Hardwrap(value, cellWidth, false), "\n")
			height = max(height, len(cells[i]))
		}
		for line := 0; line < height; line++ {
			out.WriteString("│")
			for _, cell := range cells {
				value := ""
				if line < len(cell) {
					value = ansi.Truncate(cell[line], cellWidth, "")
				}
				out.WriteString(" " + value + strings.Repeat(" ", max(0, cellWidth-ansi.StringWidth(value))) + " │")
			}
			out.WriteByte('\n')
		}
	}
	out.WriteString(rule("┌", "┬", "┐"))
	row(cols[start:end])
	out.WriteString(rule("├", "┼", "┤"))
	for i, record := range data {
		values := make([]string, visible)
		for j := range values {
			idx := start + j
			if idx >= len(record) || record[idx] == nil {
				values[j] = "NULL"
			} else {
				values[j] = fmt.Sprint(record[idx])
			}
		}
		row(values)
		if i+1 < len(data) {
			out.WriteString(rule("├", "┼", "┤"))
		}
	}
	out.WriteString(rule("└", "┴", "┘"))
	out.WriteString(fmt.Sprintf("Строк: %d · столбцы %d–%d из %d", len(data), start+1, end, len(cols)))
	if truncated {
		out.WriteString(" · вывод ограничен")
	}
	return out.String()
}
