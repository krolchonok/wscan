package tui

import (
	"errors"
	"strings"
	"testing"
	"wscan/internal/engine/js"
)

func browserTestResult(cols []string, rows [][]any) map[string]any {
	return map[string]any{"ResultSets": []map[string]any{{"Columns": cols, "Rows": rows, "Count": len(rows), "Truncated": false}}}
}
func TestSQLBrowserTableSelection(t *testing.T) {
	for _, dialect := range []string{"mysql", "pg"} {
		b := sqlBrowserState{}
		b.apply("browse-tables", browserTestResult([]string{"schema", "name", "type"}, [][]any{{"app", "users", "BASE TABLE"}, {"app", "notes", "VIEW"}}), 0)
		m := model{screen: dialect + "-console"}
		if dialect == "mysql" {
			m.mysqlConsole.browser = b
			m.mysqlConsole.session = &js.MySQLSession{}
		} else {
			m.pgConsole.browser = b
			m.pgConsole.session = &js.PGSession{}
		}
		got, _ := m.updateSQLBrowser(dialect, "down")
		m = got.(model)
		got, cmd := m.updateSQLBrowser(dialect, "enter")
		m = got.(model)
		if cmd == nil {
			t.Fatal("selection did not start query")
		}
		browser := m.pgConsole.browser
		if dialect == "mysql" {
			browser = m.mysqlConsole.browser
		}
		if browser.selected.name != "notes" {
			t.Fatalf("wrong selection %+v", browser.selected)
		}
		// No command is run: this test checks navigation without network access.
		if dialect == "mysql" {
			m.mysqlConsole.busy = false
			m.mysqlConsole.browser.mode = "rows"
		} else {
			m.pgConsole.busy = false
			m.pgConsole.browser.mode = "rows"
		}
		got, _ = m.updateSQLBrowser(dialect, "esc")
		m = got.(model)
		browser = m.pgConsole.browser
		if dialect == "mysql" {
			browser = m.mysqlConsole.browser
		}
		if browser.mode != "tables" {
			t.Fatal("back did not preserve table list")
		}
	}
}
func TestSQLBrowserPaging(t *testing.T) {
	rows := make([][]any, 101)
	for i := range rows {
		rows[i] = []any{i}
	}
	b := sqlBrowserState{}
	result := browserTestResult([]string{"id"}, rows)
	b.apply("browse-rows", result, 2)
	_, data, _ := sqlBrowserRows(b.result)
	if b.page != 2 || !b.hasNext || len(data) != 100 {
		t.Fatal("page limit")
	}
	b.apply("browse-rows", browserTestResult([]string{"id"}, [][]any{{201}}), 3)
	if b.hasNext || b.page != 3 {
		t.Fatal("end of data")
	}
	m := model{screen: "mysql-console", mysqlConsole: mysqlConsoleState{browser: b}}
	got, cmd := m.updateSQLBrowser("mysql", "right")
	if cmd != nil || got.(model).mysqlConsole.browser.page != 3 {
		t.Fatal("advanced beyond last page")
	}
}
func TestSQLBrowserQuotesServerIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		dialect string
		table   sqlBrowserTable
		want    string
	}{{"mysql", sqlBrowserTable{schema: "app", name: "odd`table"}, "SELECT * FROM `app`.`odd``table` LIMIT 101 OFFSET 100"}, {"pg", sqlBrowserTable{schema: "public", name: `odd"table`}, `SELECT * FROM "public"."odd""table" LIMIT 101 OFFSET 100`}} {
		if got := sqlBrowserQuery("browse-rows", tc.dialect, tc.table, 1); got != tc.want {
			t.Fatalf("%s", got)
		}
	}
}
func TestSQLBrowserStaleAndFailedResultsDoNotReplacePage(t *testing.T) {
	result := browserTestResult([]string{"id"}, [][]any{{1}})
	m := model{screen: "mysql-console", mysqlConsole: mysqlConsoleState{generation: 3, browser: sqlBrowserState{mode: "rows", page: 1, result: result}}}
	got, _ := m.applyMySQLDone(mysqlDone{generation: 2, operation: "browse-rows", page: 2, result: browserTestResult([]string{"id"}, [][]any{{2}})})
	m = got.(model)
	if m.mysqlConsole.browser.page != 1 {
		t.Fatal("stale page applied")
	}
	got, _ = m.applyMySQLDone(mysqlDone{generation: 3, operation: "browse-rows", page: 2, err: errors.New("denied")})
	m = got.(model)
	if m.mysqlConsole.browser.page != 1 || !strings.Contains(m.message, "denied") {
		t.Fatal("failed page replaced data")
	}
}
func TestSQLBrowserEmptyListsAndColumns(t *testing.T) {
	b := sqlBrowserState{}
	b.apply("browse-databases", browserTestResult([]string{"Database"}, nil), 0)
	m := model{mysqlConsole: mysqlConsoleState{browser: b}}
	got, cmd := m.updateSQLBrowser("mysql", "enter")
	if cmd != nil || got.(model).message != "Список пуст" {
		t.Fatal("empty selection")
	}
	b.apply("browse-columns", browserTestResult([]string{"id", "name"}, nil), 0)
	if !strings.Contains(b.render(100, 20), "id\nname") {
		t.Fatal("columns not visible")
	}
}
