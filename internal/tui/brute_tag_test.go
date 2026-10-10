package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"wscan/internal/catalog"
)

// TestIsBruteEntryMatchesCredentialGuessingType pins the link between
// library/tools/gen_categories.py's "Подбор учётных данных" type label
// (shared by http/default-logins, javascript/default-logins,
// network/default-login and NSE's own "brute" category) and the catalog
// list's [БРУТ] badge, added so a credential-guessing check is visible while
// browsing by service/impact, not only on the separate "by type" axis.
func TestIsBruteEntryMatchesCredentialGuessingType(t *testing.T) {
	if !isBruteEntry(catalog.Entry{Type: "Подбор учётных данных"}) {
		t.Fatal("expected exact type match to be recognized as a brute entry")
	}
	if !isBruteEntry(catalog.Entry{Category: "Подбор учётных данных"}) {
		t.Fatal("expected Category fallback to also be recognized")
	}
	if isBruteEntry(catalog.Entry{Type: "JavaScript"}) {
		t.Fatal("an unrelated type must not be flagged as a brute entry")
	}
	if isBruteEntry(catalog.Entry{}) {
		t.Fatal("an empty entry must not be flagged as a brute entry")
	}
}

// TestBruteBadgeSurvivesListRowRendering ensures the inline [БРУТ] badge
// actually shows up in the rendered row text at a realistic terminal width
// (not swallowed by ansi.Truncate's width accounting, which is the exact
// class of bug a naively-appended ANSI-colored suffix could introduce).
func TestBruteBadgeSurvivesListRowRendering(t *testing.T) {
	entry := catalog.Entry{Path: "javascript/default-logins/smb-default-login.yaml", Type: "Подбор учётных данных"}
	line := "[ ]  " + entry.Path
	if isBruteEntry(entry) {
		line += " " + bruteTagStyle.Render("[БРУТ]")
	}
	rendered := renderListRow(line, false, 100)
	plain := ansi.Strip(rendered)
	if !strings.Contains(plain, "[БРУТ]") {
		t.Fatalf("badge missing from rendered row: %q", plain)
	}
	if !strings.Contains(plain, entry.Path) {
		t.Fatalf("path missing from rendered row: %q", plain)
	}
}
