package tui

import (
	"strings"
	"testing"
)

func TestMSSQLActionsNavigationAndGates(t *testing.T) {
	m := newTestModelForCredentials(t)
	m.screen = "mssql-console"
	got, _ := m.updateMSSQL("enter")
	m = got.(model)
	if m.screen != "mssql-actions" || !strings.Contains(m.viewMSSQLActions(100), "Прочитать строки") {
		t.Fatal("menu missing")
	}
	got, _ = m.updateMSSQL("up")
	m = got.(model)
	if m.mssqlConsole.actionIndex != len(mssqlActions)-1 {
		t.Fatal("menu wrap")
	}
	m.mssqlConsole.actionIndex = 5
	got, _ = m.updateMSSQL("enter")
	m = got.(model)
	if m.inputAction != "mssql-rows" {
		t.Fatal("rows action")
	}
	m.screen = "mssql-actions"
	m.mssqlConsole.actionIndex = 10
	m.current.AllowExploit = false
	got, cmd := m.updateMSSQL("enter")
	m = got.(model)
	if cmd != nil || m.screen == "mssql-xp-confirm" {
		t.Fatal("enable bypassed gate")
	}
	m.screen = "mssql-actions"
	m.current.AllowExploit = true
	got, _ = m.updateMSSQL("enter")
	m = got.(model)
	if m.screen != "mssql-xp-confirm" {
		t.Fatal("enable needs confirmation")
	}
	got, cmd = m.updateMSSQL("esc")
	m = got.(model)
	if cmd != nil || m.screen != "mssql-actions" {
		t.Fatal("cancel executed operation")
	}
	if q := mssqlCommandQuery("echo 'test'"); q != "EXEC master.dbo.xp_cmdshell N'echo ''test'''" {
		t.Fatal("command not escaped")
	}
}
