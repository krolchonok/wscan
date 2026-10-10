package tui

import (
	"testing"

	"wscan/internal/catalog"
	"wscan/internal/domain"
)

func newTestModelForCatalog() model {
	var m model
	m.entries = []catalog.Entry{{Path: "http/foo.yaml", Type: "Test"}}
	m.catalogAxis = "type"
	m.applyFilter()
	return m
}

// In the one-off scan picker (catalogPending), Enter must launch straight
// away regardless of where the cursor sits in the list — the user should
// never need to navigate down to a trailing "Запустить" row first. Space
// stays the only selection key.
func TestUpdateCatalogEnterLaunchesImmediatelyWhenPending(t *testing.T) {
	m := newTestModelForCatalog()
	m.catalogPending = true
	m.entryIndex = 0 // cursor on the first real entry, NOT a trailing row
	svc := domain.Service{Host: "10.0.0.10", Port: 80}
	m.actionService = &svc
	m.pendingTemplateIDs = []string{"http/foo.yaml"}

	got, cmd := m.updateCatalog("enter")
	m2 := got.(model)
	if cmd != nil {
		t.Fatal("enter must launch synchronously (openScanReview), not return a toggle command")
	}
	if m2.screen != "scan-review" {
		t.Fatalf("enter must open scan review immediately, got screen=%q", m2.screen)
	}
}

// Enter must still report the "nothing selected" message (via
// openScanReview) rather than toggling the highlighted entry, confirming it
// never falls back to toggle behavior in pending mode even when selection is
// empty.
func TestUpdateCatalogEnterWithNoSelectionStillGoesThroughLaunchPath(t *testing.T) {
	m := newTestModelForCatalog()
	m.screen = "catalog"
	m.catalogPending = true
	m.entryIndex = 0
	svc := domain.Service{Host: "10.0.0.10", Port: 80}
	m.actionService = &svc
	m.pendingTemplateIDs = nil

	got, cmd := m.updateCatalog("enter")
	m2 := got.(model)
	if cmd != nil {
		t.Fatal("enter must not fall back to a toggle command in pending mode")
	}
	if m2.screen != "catalog" {
		t.Fatalf("with nothing selected, launch must stay on catalog with a message, got screen=%q", m2.screen)
	}
	if m2.message == "" {
		t.Fatal("expected a 'nothing selected' message from openScanReview")
	}
}

// Outside the one-off picker (editing the project's persistent template
// library), there's no scan to launch — Enter keeps toggling the highlighted
// entry, same as Space, exactly as before this change.
func TestUpdateCatalogEnterStillTogglesWhenNotPending(t *testing.T) {
	m := newTestModelForCatalog()
	m.catalogPending = false
	m.entryIndex = 0

	_, cmd := m.updateCatalog("enter")
	if cmd == nil {
		t.Fatal("enter must still toggle the entry (return a toggle command) outside the scan picker")
	}
}

// Left arrow is an alias for Esc: back out to the category list.
func TestUpdateCatalogLeftArrowGoesBackToGroups(t *testing.T) {
	m := newTestModelForCatalog()
	m.screen = "catalog"

	got, _ := m.updateCatalog("left")
	m2 := got.(model)
	if m2.screen != "catalog-groups" {
		t.Fatalf("left arrow must back out to catalog-groups, got screen=%q", m2.screen)
	}
}

// Right arrow drills into the highlighted category, same as Enter used to.
func TestUpdateCatalogGroupsRightArrowDrillsIn(t *testing.T) {
	m := newTestModelForCatalog()
	m.catalogGroupIndex = 0

	got, _ := m.updateCatalogGroups("right")
	m2 := got.(model)
	if m2.screen != "catalog" {
		t.Fatalf("right arrow must drill into the category, got screen=%q", m2.screen)
	}
}

// In the one-off scan picker, Enter on the groups screen must also launch
// immediately — it must not drill into the highlighted category.
func TestUpdateCatalogGroupsEnterLaunchesImmediatelyWhenPending(t *testing.T) {
	m := newTestModelForCatalog()
	m.catalogPending = true
	m.catalogGroupIndex = 0
	svc := domain.Service{Host: "10.0.0.10", Port: 80}
	m.actionService = &svc
	m.pendingTemplateIDs = []string{"http/foo.yaml"}

	got, cmd := m.updateCatalogGroups("enter")
	m2 := got.(model)
	if cmd != nil {
		t.Fatal("enter must launch synchronously, not drill in")
	}
	if m2.screen != "scan-review" {
		t.Fatalf("enter must open scan review immediately, got screen=%q", m2.screen)
	}
}
