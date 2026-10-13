package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"wscan/internal/catalog"
)

func TestInteractionMenuContainsOnlyConnectionTools(t *testing.T) {
	m := model{width: 140, height: 50}
	view := ansi.Strip(m.viewInteractionMenu(140))
	for _, duplicate := range []string{"CVE", "NSE --script vuln", "AD Scan", "Kerberos", "Coerce / Responder"} {
		if strings.Contains(view, duplicate) {
			t.Fatalf("duplicate project operation %s in tools", duplicate)
		}
	}
	for _, tool := range []string{"SMB", "FTP", "WinRM", "MSSQL", "PostgreSQL", "MySQL", "Web LFI", "Web SQLi", "Web Upload", "SSH", "Kyocera"} {
		if !strings.Contains(view, tool) {
			t.Fatalf("connection tool lost: %s", tool)
		}
	}
}

func TestADCheckMenuDoesNotRepeatCoercion(t *testing.T) {
	m := model{width: 140, height: 50, adAccessIndex: 2}
	view := ansi.Strip(m.viewADAccess(140))
	for _, duplicate := range []string{"Coerce:", "Responder:"} {
		if strings.Contains(view, duplicate) {
			t.Fatalf("duplicate %s in AD checks", duplicate)
		}
	}
	for _, check := range []string{"LDAP-аудит", "AS-REP", "SYSVOL", "LDAP signing", "BloodHound CE"} {
		if !strings.Contains(view, check) {
			t.Fatalf("AD operation lost: %s", check)
		}
	}
}

func TestCatalogDuplicatePathsDoNotMultiplyRowsOrCounts(t *testing.T) {
	e := catalog.Entry{Path: "http/demo.yaml", Service: "Web", Type: "Web: one, Web: one", Checked: true, Available: true}
	m := model{entries: []catalog.Entry{e, e}, current: workspaceFixture().current, catalogAxis: "type"}
	m.current.TemplateIDs = []string{e.Path}
	m.applyFilter()
	if len(m.filtered) != 1 {
		t.Fatal("duplicate catalog row")
	}
	total, selected := m.groupCounts()
	if total["Web: one"] != 1 || selected["Web: one"] != 1 {
		t.Fatalf("group counts %v %v", total, selected)
	}
	if ids := m.groupTemplateIDs("Web: one"); len(ids) != 1 || ids[0] != e.Path {
		t.Fatalf("duplicate selected IDs: %v", ids)
	}
	groups := m.visibleCatalogGroups()
	if len(groups) != 1 || groups[0].Count != 1 {
		t.Fatalf("duplicate group counts: %v", groups)
	}
}

func TestObsoleteMenusUseCurrentWorkspace(t *testing.T) {
	m := workspaceFixture()
	m.width, m.height = 140, 40
	if strings.Contains(ansi.Strip(m.viewOverview(140)), "Начать проверку…") {
		t.Fatal("obsolete project menu remains")
	}
	if strings.Contains(ansi.Strip(m.viewReconHostMenu(140)), "Машина:") {
		t.Fatal("obsolete machine menu remains")
	}
}

func TestCoercionSectionRetainsProjectScopeWithoutLaunching(t *testing.T) {
	m := newTestModelForSettings(t)
	m.inventory = workspaceFixture().inventory
	m.hostOrder = nil
	m.hostIndex = -1
	m.screen = "ad-menu"
	m.adMenuIndex = 2
	next, cmd := m.updateADMenu("enter")
	m = next.(model)
	if cmd != nil || m.screen != "coerce-setup" || len(m.jobs) != 0 || len(m.coercionTargets()) == 0 {
		t.Fatal("project Coerce scope lost or executed during navigation")
	}
	if !strings.Contains(m.viewCoercionSetup(140), "Изменить цели") {
		t.Fatal("scope editor missing")
	}
}

func TestChecksSectionRetainsAllGlobalOperations(t *testing.T) {
	m := model{screen: "checks-menu", width: 140, height: 40}
	view := ansi.Strip(m.viewChecksMenu(140))
	for _, operation := range []string{"Выбрать проверки проекта", "CVE", "NSE vuln"} {
		if !strings.Contains(view, operation) {
			t.Fatalf("global operation missing: %s", operation)
		}
	}
}

func TestBackAppearsOnceInProjectMenus(t *testing.T) {
	m := workspaceFixture()
	for _, screen := range []string{"recon", "desk"} {
		m.screen = screen
		for _, index := range m.sidebarItems() {
			if index == 11 {
				t.Fatal("Back duplicates Projects on root screen")
			}
		}
	}
	for _, labels := range [][]string{adMenuActions, checksMenuActions} {
		for _, label := range labels {
			if strings.Contains(label, "Назад") {
				t.Fatal("section duplicates sidebar Back")
			}
		}
	}
}
