package tui

import (
	"testing"

	"wscan/internal/domain"
)

func TestFilterServiceInventoryFindsPortAndRecognizedService(t *testing.T) {
	rows := []serviceInventoryRow{
		{host: "10.0.0.10", service: domain.Service{Port: 445, Protocol: "tcp", Name: "microsoft-ds", Product: "Windows SMB"}},
		{host: "10.0.0.11", service: domain.Service{Port: 389, Protocol: "tcp", Name: "ldap"}},
	}
	for query, want := range map[string]int{"445": 1, "smb": 1, "LDAP": 1, "10.0.0.99": 0} {
		if got := len(filterServiceInventory(rows, query)); got != want {
			t.Errorf("filter %q: got %d rows, want %d", query, got, want)
		}
	}
}

func TestServiceInventoryCanSelectHostsAndOpenGroupedActions(t *testing.T) {
	m := model{
		screen:    "service-inventory",
		hostOrder: []string{"10.0.0.10", "10.0.0.11", "10.0.0.12"},
		inventory: map[string]*hostInfo{
			"10.0.0.10": {services: []domain.Service{{Host: "10.0.0.10", Port: 445, Protocol: "tcp", Name: "microsoft-ds"}}},
			"10.0.0.11": {services: []domain.Service{{Host: "10.0.0.11", Port: 445, Protocol: "tcp", Name: "microsoft-ds"}}},
			"10.0.0.12": {services: []domain.Service{{Host: "10.0.0.12", Port: 389, Protocol: "tcp", Name: "ldap"}}},
		},
		serviceInventoryFilter: "445",
	}
	if got := len(m.serviceInventoryRows()); got != 3 {
		t.Fatalf("inventory rows: got %d, want 3", got)
	}
	if got := len(filterServiceInventory(m.serviceInventoryRows(), m.serviceInventoryFilter)); got != 2 {
		t.Fatalf("filtered rows: got %d, want 2", got)
	}
	updated, _ := m.updateServiceInventory("a")
	m = updated.(model)
	if len(m.serviceInventorySelected) != 2 {
		t.Fatalf("select all filtered rows selected %d hosts, want 2", len(m.serviceInventorySelected))
	}
	updated, _ = m.updateServiceInventory("enter")
	m = updated.(model)
	if m.screen != "action-menu" || len(m.actionHosts) != 2 || m.actionService != nil || m.actionReturn != "service-inventory" || m.bulkPort != 445 || m.bulkProtocol != "tcp" {
		t.Fatalf("unexpected grouped action scope: screen=%q hosts=%v service=%v return=%q", m.screen, m.actionHosts, m.actionService, m.actionReturn)
	}
	rows := m.actionRows()
	foundBulk := false
	for _, row := range rows {
		foundBulk = foundBulk || row.kind == jobBulkPort
	}
	if !foundBulk {
		t.Fatalf("group action menu lacks a port-scoped check: %+v", rows)
	}
	for i, row := range rows {
		if row.kind == jobBulkPort {
			m.actionIndex = i
			break
		}
	}
	updated, _ = m.updateActionMenu("enter")
	m = updated.(model)
	if m.screen != "input" || m.input != "445/tcp" {
		t.Fatalf("group check did not preselect matching port: screen=%q input=%q", m.screen, m.input)
	}
}
