package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"wscan/internal/catalog"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/storage"
)

func testService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	c := catalog.NewWithLibrary(filepath.Join(dir, "templates"), "")
	e := engine.New(store, engine.Config{TimeoutSeconds: 2})
	s, err := NewService(context.Background(), store, c, e)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close(); store.Close() })
	return s
}
func TestSharedDiscoveryPersistsServiceAndDoesNotRepeat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "local fixture") }))
	defer server.Close()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	s := testService(t)
	id, err := s.CreateProject(context.Background(), "fixture", []string{host})
	if err != nil {
		t.Fatal(err)
	}
	request := ScanRequest{ProjectID: id, Spec: Spec{Kind: "discover", Hosts: []string{host}, DiscPorts: []int{port}, DiscNoPing: true, DiscNoVersion: true}}
	job, err := s.StartScan(context.Background(), request, "web", "once")
	if err != nil {
		t.Fatal(err)
	}
	finished := waitJob(t, s.Jobs, job.ID)
	if finished.Status != "done" {
		t.Fatalf("discovery failed: %+v", finished)
	}
	inventory, err := s.Inventory(context.Background(), id)
	if err != nil || len(inventory.Services) != 1 || inventory.Services[0].Port != port {
		t.Fatalf("inventory: %+v %v", inventory, err)
	}
	repeated, err := s.StartScan(context.Background(), request, "web", "once")
	if err != nil || repeated.ID != job.ID {
		t.Fatalf("repeat: %+v %v", repeated, err)
	}
	request.Spec.DiscPorts = []int{port + 1}
	if _, err := s.StartScan(context.Background(), request, "web", "once"); err == nil {
		t.Fatal("changed request accepted with same key")
	}
}
func TestInventoryRespectsDeletedPorts(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	id, _ := s.CreateProject(ctx, "fixture", []string{"10.20.0.10"})
	run, _ := s.Store.StartRun(ctx, id)
	service := domain.Service{Host: "10.20.0.10", Port: 445, Protocol: "tcp", Target: "10.20.0.10"}
	if err := s.Store.SaveService(ctx, run, service); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.ExcludeInventory(ctx, id, service.Host, "10.20.0.10/tcp/445", nil, nil); err != nil {
		t.Fatal(err)
	}
	inventory, err := s.Inventory(ctx, id)
	if err != nil || len(inventory.Services) != 0 {
		t.Fatalf("deleted service resurrected: %+v %v", inventory, err)
	}
}
func TestOwnerLockRejectsSecondExecutor(t *testing.T) {
	dir := t.TempDir()
	unlock, err := OwnerLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := OwnerLock(dir); err == nil {
		second()
		unlock()
		t.Fatal("two executor owners allowed")
	}
	unlock()
	again, err := OwnerLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	again()
}

func TestADProfileUsesTwoProjectHostsWithoutCIDR(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	targets := []string{"127.0.0.2", "127.0.0.3"}
	id, err := s.CreateProject(ctx, "two AD hosts", targets)
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.StartScan(ctx, ScanRequest{ProjectID: id, Spec: Spec{Kind: "ad-scan", TemplateIDs: []string{"unrelated-project-template"}}}, "web", "")
	if err != nil {
		t.Fatal(err)
	}
	finished := waitJob(t, s.Jobs, job.ID)
	if finished.Status != "done" {
		t.Fatalf("AD job failed: %+v", finished)
	}
	if finished.Outcome.AD.HostsScanned != 2 {
		t.Fatalf("scanned %d hosts, want 2", finished.Outcome.AD.HostsScanned)
	}
	project, err := s.Project(ctx, id)
	if err != nil || len(project.Targets) != 2 {
		t.Fatalf("scope expanded: %+v %v", project.Targets, err)
	}
	for _, target := range project.Targets {
		if target != targets[0] && target != targets[1] {
			t.Fatalf("unexpected scope entry %q", target)
		}
	}
}

func TestFullProfileHonorsExplicitPortsOverAllPorts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "local full fixture") }))
	defer server.Close()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	s := testService(t)
	s.entries = []catalog.Entry{} // An empty local catalogue; this fixture exercises discovery only.
	id, err := s.CreateProject(context.Background(), "full fixture", []string{host})
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.Project(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	project.AllPorts = true
	project.LockoutMaxAttempts = domain.DefaultLockoutMaxAttempts
	project.LockoutWindowMinutes = domain.DefaultLockoutWindowMinutes
	if err := s.SaveSettings(context.Background(), project); err != nil {
		t.Fatal(err)
	}
	job, err := s.StartScan(context.Background(), ScanRequest{ProjectID: id, Spec: Spec{Kind: "full", Hosts: []string{host}, DiscPorts: []int{port}, DiscNoVersion: true}}, "web", "")
	if err != nil {
		t.Fatal(err)
	}
	done := waitJob(t, s.Jobs, job.ID)
	if done.Status != "done" {
		t.Fatalf("full failed: %+v", done)
	}
	if len(done.Outcome.Result.Services) != 1 || done.Outcome.Result.Services[0].Port != port {
		t.Fatalf("full ignored explicit port: %+v", done.Outcome.Result.Services)
	}
}

func TestEmptyChecksFailBeforeCreatingJob(t *testing.T) {
	s := testService(t)
	id, err := s.CreateProject(context.Background(), "empty checks", []string{"127.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartScan(context.Background(), ScanRequest{ProjectID: id, Spec: Spec{Kind: "checks"}}, "web", ""); err == nil {
		t.Fatal("empty checks accepted")
	}
	if len(s.Jobs.List()) != 0 {
		t.Fatal("invalid request created a failed job")
	}
}
