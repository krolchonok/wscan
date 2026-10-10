package tui

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"strings"
)

const sqlBrowserPageSize = 100

type sqlBrowserTable struct{ schema, name, kind string }
type sqlBrowserState struct {
	columnOffset                     int
	mode                             string
	databases                        []string
	tables                           []sqlBrowserTable
	index, offset, page, requestPage int
	selected                         sqlBrowserTable
	result                           map[string]any
	hasNext, truncated               bool
}

func sqlBrowserRows(result map[string]any) ([]string, [][]any, bool) {
	sets, ok := result["ResultSets"].([]map[string]any)
	if !ok || len(sets) == 0 {
		return nil, nil, false
	}
	cols, _ := sets[0]["Columns"].([]string)
	rows, _ := sets[0]["Rows"].([][]any)
	truncated, _ := sets[0]["Truncated"].(bool)
	return cols, rows, truncated
}
func (b *sqlBrowserState) apply(operation string, result map[string]any, page int) {
	_, rows, truncated := sqlBrowserRows(result)
	switch operation {
	case "browse-databases":
		b.mode = "databases"
		b.databases = nil
		b.index = 0
		b.truncated = truncated
		for _, row := range rows {
			if len(row) > 0 && row[0] != nil {
				b.databases = append(b.databases, fmt.Sprint(row[0]))
			}
		}
	case "browse-tables":
		b.columnOffset = 0
		b.mode = "tables"
		b.tables = nil
		b.index = 0
		b.truncated = truncated
		for _, row := range rows {
			if len(row) >= 3 {
				b.tables = append(b.tables, sqlBrowserTable{fmt.Sprint(row[0]), fmt.Sprint(row[1]), fmt.Sprint(row[2])})
			}
		}
	case "browse-rows":
		b.mode = "rows"
		b.page = page
		b.offset = 0
		b.hasNext = len(rows) > sqlBrowserPageSize || truncated
		if len(rows) > sqlBrowserPageSize {
			sets := result["ResultSets"].([]map[string]any)
			sets[0]["Rows"] = rows[:sqlBrowserPageSize]
			sets[0]["Count"] = sqlBrowserPageSize
			sets[0]["Truncated"] = false
		}
		b.result = result
	case "browse-columns":
		b.mode = "columns"
		b.offset = 0
		b.result = result
	}
}
func sqlBrowserQuote(name, dialect string) string {
	if dialect == "mysql" {
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	}
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
func sqlBrowserQuery(operation, dialect string, table sqlBrowserTable, page int) string {
	switch operation {
	case "browse-databases":
		if dialect == "mysql" {
			return "SHOW DATABASES"
		}
		return "SELECT datname FROM pg_database WHERE datallowconn ORDER BY datname"
	case "browse-tables":
		if dialect == "mysql" {
			return "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME"
		}
		return "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA NOT IN ('pg_catalog','information_schema') ORDER BY TABLE_SCHEMA, TABLE_NAME"
	case "browse-columns":
		return "SELECT * FROM " + sqlBrowserQuote(table.schema, dialect) + "." + sqlBrowserQuote(table.name, dialect) + " WHERE 1=0"
	default:
		return fmt.Sprintf("SELECT * FROM %s.%s LIMIT %d OFFSET %d", sqlBrowserQuote(table.schema, dialect), sqlBrowserQuote(table.name, dialect), sqlBrowserPageSize+1, max(0, page)*sqlBrowserPageSize)
	}
}
func (m model) startSQLBrowser(dialect, operation string, page int) (tea.Model, tea.Cmd) {
	b := &m.pgConsole.browser
	if dialect == "mysql" {
		b = &m.mysqlConsole.browser
	}
	b.requestPage = page
	query := sqlBrowserQuery(operation, dialect, b.selected, page)
	if dialect == "mysql" {
		return m.startMySQL(operation, query)
	}
	return m.startPG(operation, query)
}
func (m model) updateSQLBrowser(dialect, key string) (tea.Model, tea.Cmd) {
	b := &m.pgConsole.browser
	if dialect == "mysql" {
		b = &m.mysqlConsole.browser
	}
	if key == "b" || key == "2" {
		return m.startSQLBrowser(dialect, "browse-databases", 0)
	}
	if key == "t" || key == "3" {
		return m.startSQLBrowser(dialect, "browse-tables", 0)
	}
	if key == "s" {
		b.mode = ""
		m.startInput(dialect + "-query")
		return m, nil
	}
	if key == "esc" || key == "q" {
		if b.mode == "rows" || b.mode == "columns" {
			b.mode = "tables"
			b.offset = 0
		} else {
			b.mode = ""
		}
		return m, nil
	}
	if b.mode == "databases" || b.mode == "tables" {
		length := len(b.tables)
		if b.mode == "databases" {
			length = len(b.databases)
		}
		switch key {
		case "up", "k":
			b.index = max(0, b.index-1)
		case "down", "j":
			b.index = min(max(0, length-1), b.index+1)
		case "home":
			b.index = 0
		case "end":
			b.index = max(0, length-1)
		case "r":
			return m.startSQLBrowser(dialect, "browse-"+b.mode, 0)
		case "enter":
			if length == 0 {
				m.message = "Список пуст"
				return m, nil
			}
			if b.mode == "databases" {
				db := b.databases[b.index]
				if dialect == "mysql" {
					return m.startMySQL("database", db)
				}
				return m.startPG("database", db)
			}
			b.selected = b.tables[b.index]
			b.columnOffset = 0
			return m.startSQLBrowser(dialect, "browse-rows", 0)
		}
		return m, nil
	}
	switch key {
	case "[":
		b.columnOffset = max(0, b.columnOffset-1)
	case "]":
		cols, _, _ := sqlBrowserRows(b.result)
		b.columnOffset = min(max(0, len(cols)-1), b.columnOffset+1)
	case "up", "k":
		b.offset = max(0, b.offset-1)
	case "down", "j":
		b.offset++
	case "pgup":
		b.offset = max(0, b.offset-10)
	case "pgdown":
		b.offset += 10
	case "home":
		b.offset = 0
	case "end":
		b.offset = 1 << 30
	case "right", "n":
		if b.mode == "rows" && b.hasNext {
			return m.startSQLBrowser(dialect, "browse-rows", b.page+1)
		}
	case "left", "p":
		if b.mode == "rows" && b.page > 0 {
			return m.startSQLBrowser(dialect, "browse-rows", b.page-1)
		}
	case "r":
		return m.startSQLBrowser(dialect, "browse-rows", b.page)
	case "c":
		return m.startSQLBrowser(dialect, "browse-columns", b.page)
	case "enter":
		if b.mode == "columns" {
			return m.startSQLBrowser(dialect, "browse-rows", b.page)
		}
	}
	return m, nil
}
func (b sqlBrowserState) render(w, rows int) string {
	body := ""
	if b.mode == "databases" || b.mode == "tables" {
		label := "Таблицы"
		length := len(b.tables)
		if b.mode == "databases" {
			label = "Базы"
			length = len(b.databases)
		}
		body = label + " · ↑/↓ выбор · Enter открыть · b базы · r обновить · s SQL · Esc консоль\n"
		lo, hi := windowRange(b.index, length, max(1, rows-4))
		for i := lo; i < hi; i++ {
			name := ""
			if b.mode == "databases" {
				name = b.databases[i]
			} else {
				t := b.tables[i]
				name = t.schema + "." + t.name + " · " + t.kind
			}
			body += renderListRow(sanitizeWinRMText(name), b.index == i, w)
		}
		if length == 0 {
			body += "Список пуст. Проверь выбранную базу и права учётки.\n"
		}
		if b.truncated {
			body += "Показаны первые 500 записей.\n"
		}
		return body
	}
	body = fmt.Sprintf("%s.%s · страница %d · по %d строк\n", sanitizeWinRMText(b.selected.schema), sanitizeWinRMText(b.selected.name), b.page+1, sqlBrowserPageSize)
	body += "←/→ страницы · ↑/↓ прокрутка · [/] столбцы · c список · b базы · r данные · Esc таблицы\n"
	text := sqlDataTable(b.result, max(5, w-6), b.columnOffset)
	if b.mode == "columns" {
		cols, _, _ := sqlBrowserRows(b.result)
		text = "Столбцы:\n" + strings.Join(cols, "\n") + "\nEnter — данные"
	}
	lines := strings.Split(ansi.Wrap(text, max(1, w-6), ""), "\n")
	count := max(1, rows-4)
	lo := min(b.offset, max(0, len(lines)-count))
	return body + strings.Join(lines[lo:min(len(lines), lo+count)], "\n")
}
