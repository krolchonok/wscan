package tui

import (
	"strings"
	"testing"
)

func TestMSSQLReadAliases(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{":db", "DB_NAME()"}, {":tables", "INFORMATION_SCHEMA.TABLES"},
		{":rows users", "SELECT TOP (100) * FROM [dbo].[users]"},
		{":rows sales.orders 25", "SELECT TOP (25) * FROM [sales].[orders]"},
		{":count dbo.users", "SELECT COUNT_BIG(*) AS row_count FROM [dbo].[users]"},
		{":columns dbo.users", "TABLE_NAME=N'users'"},
	} {
		q, a, e := mssqlReadAlias(tc.input)
		if e != nil || !a || !strings.Contains(q, tc.want) {
			t.Fatalf("%s: %q %v", tc.input, q, e)
		}
	}
	for _, input := range []string{":rows dbo.users;DROP", ":rows other.dbo.users", ":rows users 501", ":rows users 0", ":rows users -1", ":count users extra", ":columns users'", ":tables extra", ":unknown"} {
		_, a, e := mssqlReadAlias(input)
		if !a || e == nil {
			t.Fatalf("accepted invalid alias: %s", input)
		}
	}
	if _, a, e := mssqlReadAlias("SELECT 1"); a || e != nil {
		t.Fatal("raw SQL classified as alias")
	}
}

func TestMSSQLRawSQLRemainsGated(t *testing.T) {
	m := newTestModelForCredentials(t)
	m.current.AllowExploit = false
	got, cmd := m.startMSSQL("query", "SELECT 1")
	if cmd != nil || !strings.Contains(got.(model).message, "AllowExploit") {
		t.Fatal("raw SQL bypassed gate")
	}
	got, cmd = m.startMSSQL("query", ":rows users")
	if cmd != nil || got.(model).message != "Подключись к MSSQL" {
		t.Fatal("read alias did not pass SQL gate")
	}
}
