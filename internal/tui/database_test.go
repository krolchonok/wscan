package tui

import (
	"testing"
	"wscan/internal/catalog"
	"wscan/internal/domain"
)

func TestDatabaseMenuNavigationAndSelection(t *testing.T) {
	m := model{catalogAxis: "direction", entries: []catalog.Entry{
		{Path: "javascript/enumeration/redis/redis-info.yaml", Service: "Базы данных", Checked: true, Available: true},
		{Path: "nmap/scripts/mysql-info.nse", Service: "Базы данных", Checked: true, Available: true},
		{Path: "javascript/default-logins/redis-default-logins.yaml", Service: "Базы данных", Type: bruteCategoryLabel, Checked: true, Available: true},
	}}
	next, _ := m.drillCatalogGroup([]libraryGroup{{Name: "Базы данных"}})
	m = next.(model)
	if m.catalogAxis != "database" {
		t.Fatalf("axis = %s", m.catalogAxis)
	}
	var redisIndex int
	groups := m.visibleCatalogGroups()
	for i, g := range groups {
		if g.Name == "Redis" {
			redisIndex = i
		}
	}
	m.catalogGroupIndex = redisIndex
	if ids := m.groupTemplateIDs("Redis"); len(ids) != 1 || ids[0] != m.entries[0].Path {
		t.Fatalf("Redis selection = %v", ids)
	}
	next, _ = m.drillCatalogGroup(groups)
	m = next.(model)
	if m.catalogDatabase != "Redis" || m.catalogAxis != "impact" {
		t.Fatalf("database=%s axis=%s", m.catalogDatabase, m.catalogAxis)
	}
	m.applyFilter()
	if len(m.filtered) != 2 {
		t.Fatalf("Redis filter = %v", m.filtered)
	}
	if ids := m.groupTemplateIDs(bruteCategoryLabel); len(ids) != 1 || ids[0] != m.entries[2].Path {
		t.Fatalf("Redis brute = %v", ids)
	}
	next, _ = m.updateCatalogGroups("left")
	m = next.(model)
	if m.catalogAxis != "database" || m.catalogDatabase != "" {
		t.Fatal("back did not restore DB types")
	}
	next, _ = m.updateCatalogGroups("left")
	m = next.(model)
	if m.catalogAxis != "direction" || m.catalogDirection != "" {
		t.Fatal("back did not restore services")
	}
}

func TestDatabasePortFilteringAndMixedBulk(t *testing.T) {
	entries := []catalog.Entry{
		{Path: "javascript/default-logins/redis-default-logins.yaml", Service: "Базы данных", Product: "Airflow"},
		{Path: "javascript/default-logins/mysql-default-login.yaml", Service: "Базы данных"},
		{Path: "javascript/default-logins/mssql-default-logins.yaml", Service: "Базы данных"},
	}
	ids := []string{entries[0].Path, entries[1].Path, entries[2].Path}
	redis := domain.Service{Name: "redis", Port: 6379}
	allowed, skipped := portCompatibleTemplateIDs(entries, redis, ids)
	if len(allowed) != 1 || allowed[0] != ids[0] || len(skipped) != 2 {
		t.Fatalf("allowed=%v skipped=%v", allowed, skipped)
	}
	allowed, skipped = servicesCompatibleTemplateIDs(entries, []domain.Service{redis, {Name: "mysql", Port: 6379}}, ids)
	if len(allowed) != 2 || len(skipped) != 1 || skipped[0] != ids[2] {
		t.Fatalf("mixed allowed=%v skipped=%v", allowed, skipped)
	}
	allowed, _ = portCompatibleTemplateIDs(entries, domain.Service{Name: "unknown", Port: 45678}, ids)
	if len(allowed) != 3 {
		t.Fatal("unknown service prevents manual DB selection")
	}
}
