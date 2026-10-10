package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"testing"
	"wscan/internal/domain"
	"wscan/internal/engine/js"
)

func TestMySQLAliases(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{":rows users 20", "SELECT * FROM `users` LIMIT 20"}, {":rows app.users", "SELECT * FROM `app`.`users` LIMIT 100"}, {":count users", "SELECT COUNT(*) AS row_count FROM `users`"}, {":db", "SELECT DATABASE(), CURRENT_USER()"}} {
		q, a, e := mysqlReadAlias(tc.input)
		if e != nil || !a || q != tc.want {
			t.Fatalf("%s: %s %v", tc.input, q, e)
		}
	}
	for _, input := range []string{":rows users 501", ":rows users 0", ":columns a.b.c", ":rows users;DROP", ":count users'", ":tables extra"} {
		if _, _, err := mysqlReadAlias(input); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	q, _, _ := mysqlReadAlias(":columns users")
	if q != "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users' ORDER BY ORDINAL_POSITION" {
		t.Fatal(q)
	}
}
func TestMySQLSelectedServiceSetupAndClose(t *testing.T) {
	m := newTestModelForSettings(t)
	m.hostOrder = []string{"127.0.0.1"}
	m.inventory = map[string]*hostInfo{"127.0.0.1": {services: []domain.Service{{Host: "127.0.0.1", Port: 3307, Name: "mysql", Protocol: "tcp"}}}}
	m.focusCol = 1
	m.openInteractionMenu()
	if m.interactionIndex != 6 {
		t.Fatal("selected MySQL service not focused")
	}
	got, cmd := m.updateInteractionMenu("enter")
	m = got.(model)
	if cmd != nil || m.screen != "mysql-setup" || m.mysqlConsole.options.Port != 3307 || m.mysqlConsole.options.SSLMode != "true" {
		t.Fatal("incorrect setup")
	}
	got, _ = m.updateMySQL("s")
	m = got.(model)
	if m.mysqlConsole.options.SSLMode != "skip-verify" {
		t.Fatal("TLS toggle")
	}
	m.mysqlConsole.options.Password = "secret"
	got, _ = m.updateMySQL("esc")
	m = got.(model)
	if m.screen != "interaction-menu" || m.mysqlConsole.options.Password != "" {
		t.Fatal("password retained")
	}
}
func TestMySQLCancellationAndStaleResult(t *testing.T) {
	cancelled := false
	m := model{screen: "mysql-console", mysqlConsole: mysqlConsoleState{busy: true, generation: 1, cancel: func() { cancelled = true }, options: js.MySQLSessionOptions{Password: "secret"}}}
	got, _ := m.updateMySQL("esc")
	m = got.(model)
	if !cancelled || m.mysqlConsole.busy || m.screen != "mysql-setup" {
		t.Fatal("cancellation failed")
	}
	got, _ = m.applyMySQLDone(mysqlDone{generation: 1, text: "stale"})
	if got.(model).mysqlConsole.transcript != "" {
		t.Fatal("stale result applied")
	}
}
func TestMySQLEmptyUsernameAndDatabaseInput(t *testing.T) {
	m := model{screen: "input", inputReturn: "mysql-setup", inputAction: "mysql-user", mysqlConsole: mysqlConsoleState{options: js.MySQLSessionOptions{Username: "root", Database: "app"}}}
	got, _ := m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = got.(model)
	if m.mysqlConsole.options.Username != "" {
		t.Fatal("empty username rejected")
	}
	m.startInput("mysql-database")
	got, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEnter})
	if got.(model).mysqlConsole.options.Database != "" {
		t.Fatal("empty database rejected")
	}
}
