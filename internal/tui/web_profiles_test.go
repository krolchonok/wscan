package tui

import (
	"testing"

	"wscan/internal/catalog"
)

func TestWebProfileSelectionKeepsBruteAndUnsupportedSeparate(t *testing.T) {
	const profile = "Web: Общий кандидат"
	m := model{catalogAxis: "type", catalogDirection: "Web", entries: []catalog.Entry{
		{Path: "env.yaml", Service: "Web", Type: "Утечки, " + profile, Checked: true, Available: true},
		{Path: "other.yaml", Service: "Web", Type: "Утечки", Checked: true, Available: true},
		{Path: "brute.yaml", Service: "Web", Type: bruteCategoryLabel + ", " + profile, Checked: true, Available: true},
		{Path: "unsupported.yaml", Service: "Web", Type: "Утечки, " + profile, Checked: true, Available: false},
	}}
	ids := m.groupTemplateIDs(profile)
	if len(ids) != 1 || ids[0] != "env.yaml" {
		t.Fatalf("profile selected %v, want only supported non-brute env check", ids)
	}
	m.catalogCategory = profile
	m.applyFilter()
	if len(m.filtered) != 1 || m.filtered[0].Path != "env.yaml" {
		t.Fatalf("profile filter returned %v", m.filtered)
	}
	if ids := m.groupTemplateIDs("Утечки"); len(ids) != 2 {
		t.Fatalf("original type selection returned %v", ids)
	}
}
