package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"wscan/internal/catalog"
	"wscan/internal/domain"
	"wscan/internal/storage"
)

func TestVersionCVEMenuNeedsNoSelectedHost(t *testing.T) {
	m := model{current: domain.Project{ID: 1}, checkMenuIndex: 1, screen: "checks-menu"}
	got, _ := m.updateChecksMenu("enter")
	m = got.(model)
	if !strings.Contains(m.message, "Нет сохранённых сервисов") {
		t.Fatal(m.message)
	}
	m.width = 110
	m.height = 24
	if !strings.Contains(m.viewChecksMenu(100), "сохранённым версиям") {
		t.Fatal("selected offline action is not visible")
	}
}
func TestVersionCVEProjectPersistence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, e := storage.Open(filepath.Join(dir, "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	id, e := store.CreateProject(ctx, "offline")
	if e != nil {
		t.Fatal(e)
	}
	// A valid empty range database exercises coverage reporting without any target connection.
	data := `{"schema_version":1,"products":{"gitlab/gitlab":{"vendor":"gitlab","product":"gitlab","aliases":["GitLab"]}},"checks":{}}`
	if e = os.WriteFile(filepath.Join(dir, "products.json"), []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	a := domain.Service{Host: "invalid.invalid", Port: 80, Protocol: "tcp", Product: "nginx", Version: "1.24"}
	b := domain.Service{Host: "192.0.2.2", Port: 22, Protocol: "tcp"}
	m := model{ctx: ctx, current: domain.Project{ID: id}, store: store, cat: catalog.NewWithLibrary(dir, dir), inventory: map[string]*hostInfo{"alias": {services: []domain.Service{a}}, a.Host: {services: []domain.Service{a}}, b.Host: {services: []domain.Service{b}}}, jobEvents: make(chan jobEvent, 16), checkMenuIndex: 1}
	got, _ := m.updateChecksMenu("enter")
	m = got.(model)
	if m.screen != "jobs" || len(m.jobs) != 1 || m.jobs[0].kind != "version-cve" {
		t.Fatal("offline job was not launched")
	}
	var event jobEvent
	for {
		event = <-m.jobEvents
		if event.done {
			break
		}
	}
	if event.err != nil || len(event.result.Services) != 2 || len(event.result.Findings) != 2 || event.result.TargetsScanned != 0 {
		t.Fatalf("%+v", event)
	}
	saved, e := store.Findings(ctx, event.result.RunID)
	if e != nil || len(saved) != 2 {
		t.Fatalf("%v %d", e, len(saved))
	}
	m.absorb(event.result.Services, saved, nil, event.result.RunID)
	if len(m.findingsForService(a.Host, a)) != 1 || len(m.findingsForService(b.Host, b)) != 1 {
		t.Fatal("offline findings lost their service ports")
	}
	for _, f := range saved {
		if f.Protocol != "offline" || f.Severity != "info" {
			t.Fatal(f)
		}
	}
}
