package tui

import (
	"testing"

	"wscan/internal/catalog"
)

// TestImpactAxisCarvesOutBruteBucket reproduces the exact screen the user
// pointed at: drilled into a service (SMB) on the "by impact" axis, which
// before this change only ever showed Обнаружение/Активные проверки/
// Сильное воздействие. A credential-guessing check like
// smb-default-login.yaml (tagged "bruteforce", which catalog.Impact already
// classifies as "Сильное воздействие") is now carved out of that bucket
// into its own "Подбор учётных данных" bucket instead — mirroring how
// catalog.IsUnsupported entries are already carved out of the normal
// buckets a few lines above in groupValues.
func TestImpactAxisCarvesOutBruteBucket(t *testing.T) {
	m := model{
		catalogAxis:      "impact",
		catalogDirection: "SMB",
		entries: []catalog.Entry{
			{Path: "javascript/enumeration/smb/smb-os-detect.yaml", Service: "SMB", Type: "JavaScript", Checked: true, Available: true},
			{Path: "nmap/scripts/smb-vuln-ms17-010.nse", Service: "SMB", Type: "Уязвимости, Безопасные проверки", Checked: true, Available: true},
			{Path: "javascript/default-logins/smb-default-login.yaml", Service: "SMB", Type: "Подбор учётных данных", Checked: true, Available: true},
		},
	}

	byName := map[string]libraryGroup{}
	for _, g := range m.visibleCatalogGroups() {
		byName[g.Name] = g
	}

	brute, ok := byName[bruteCategoryLabel]
	if !ok {
		t.Fatalf("expected a %q bucket, got groups=%v", bruteCategoryLabel, byName)
	}
	if brute.Count != 1 {
		t.Fatalf("expected exactly the one brute entry in its own bucket, got count=%d", brute.Count)
	}

	ids := m.groupTemplateIDs(bruteCategoryLabel)
	if len(ids) != 1 || ids[0] != "javascript/default-logins/smb-default-login.yaml" {
		t.Fatalf("groupTemplateIDs(%q) = %v", bruteCategoryLabel, ids)
	}

	// Opening the dedicated group must show its entries. catalog.Impact for
	// default-login checks can differ from the dedicated category label.
	m.catalogImpact = bruteCategoryLabel
	m.applyFilter()
	if len(m.filtered) != 1 || m.filtered[0].Path != ids[0] {
		t.Fatalf("brute group filter = %v, want only %q", m.filtered, ids[0])
	}

	// The brute entry must not also linger in its old impact bucket —
	// a carve-out, not an additional overlay.
	if strong, ok := byName[catalog.ImpactStrong]; ok {
		for _, id := range m.groupTemplateIDs(catalog.ImpactStrong) {
			if id == "javascript/default-logins/smb-default-login.yaml" {
				t.Fatalf("brute entry still present in %q (count=%d): not a clean carve-out", catalog.ImpactStrong, strong.Count)
			}
		}
	}
}

func TestBruteEntriesAreSeparateFromServiceBulkSelection(t *testing.T) {
	m := model{
		catalogAxis: "direction",
		entries: []catalog.Entry{
			{Path: "javascript/enumeration/smb/smb-os-detect.yaml", Service: "SMB", Type: "JavaScript", Checked: true, Available: true},
			{Path: "javascript/default-logins/smb-default-login.yaml", Service: "SMB", Type: bruteCategoryLabel, Checked: true, Available: true},
		},
	}

	if got := m.groupValues(m.entries[1]); len(got) != 1 || got[0] != bruteCategoryLabel {
		t.Fatalf("brute group values = %v, want only %q", got, bruteCategoryLabel)
	}
	if got := m.groupTemplateIDs("SMB"); len(got) != 1 || got[0] != m.entries[0].Path {
		t.Fatalf("SMB bulk selection = %v, want only the non-brute check", got)
	}
	if got := m.groupTemplateIDs(bruteCategoryLabel); len(got) != 1 || got[0] != m.entries[1].Path {
		t.Fatalf("brute selection = %v, want only the brute check", got)
	}
}
