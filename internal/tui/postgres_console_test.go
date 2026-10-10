package tui

import (
	"strings"
	"testing"
	"wscan/internal/engine/js"
)

func TestPGReadAliases(t *testing.T) {
	for _, tc := range []struct{ input, want string }{{":rows users 20", `SELECT * FROM "public"."users" LIMIT 20`}, {":count public.users", `SELECT COUNT(*) AS row_count FROM "public"."users"`}, {":db", "SELECT current_database(), current_user"}} {
		q, alias, err := pgReadAlias(tc.input)
		if err != nil || !alias || q != tc.want {
			t.Fatalf("%s: %q %t %v", tc.input, q, alias, err)
		}
	}
	for _, input := range []string{":rows users 501", ":rows users 0", ":rows users;DROP", ":columns public.users'", ":count a.b.c"} {
		if _, _, err := pgReadAlias(input); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
	q, _, err := pgReadAlias(":columns public.users")
	if err != nil || strings.Contains(q, "N'") {
		t.Fatalf("invalid PG columns query %s %v", q, err)
	}
}
func TestPGMenuAndSetup(t *testing.T) {
	m := model{screen: "interaction-menu", interactionIndex: 4}
	got, _ := m.updateInteractionMenu("down")
	m = got.(model)
	if m.interactionIndex != 5 {
		t.Fatal("PG menu missing")
	}
	m.interactionIndex = interactionMenuCount - 1
	got, _ = m.updateInteractionMenu("down")
	if got.(model).interactionIndex != 0 {
		t.Fatal("menu wrap")
	}
	m = model{screen: "pg-setup", pgConsole: pgConsoleState{options: js.PGOptions{SSLMode: "require", Password: "secret"}}}
	got, _ = m.updatePG("s")
	if got.(model).pgConsole.options.SSLMode != "verify-full" {
		t.Fatal("TLS mode")
	}
	got, _ = m.updatePG("esc")
	m = got.(model)
	if m.screen != "interaction-menu" || m.pgConsole.options.Password != "" {
		t.Fatal("close retained password")
	}
}
func TestPGStaleCompletion(t *testing.T) {
	m := model{screen: "pg-setup", pgConsole: pgConsoleState{generation: 3, busy: true}}
	got, _ := m.applyPGDone(pgDone{generation: 2, text: "stale"})
	b := got.(model).pgConsole
	if !b.busy || b.transcript != "" {
		t.Fatal("stale completion applied")
	}
}
