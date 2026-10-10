package tui

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"wscan/internal/catalog"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/storage"
)

func TestSinglePortInputValidation(t *testing.T) {
	for _, value := range []string{"0", "65536", "445,139", "445/http", "445/tcp/udp", "no"} {
		if _, _, err := parseSinglePort(value); err == nil {
			t.Fatalf("accepted invalid port %q", value)
		}
	}
	for _, value := range []string{"445", "445/tcp", "445/udp"} {
		port, _, err := parseSinglePort(value)
		if err != nil || port != 445 {
			t.Fatalf("parse %q: %d %v", value, port, err)
		}
	}
}

func TestBulkPortFilterExcludesOtherPortsAndProtocols(t *testing.T) {
	m := model{actionHosts: []string{"a", "b", "c"}, bulkPort: 445, bulkProtocol: "tcp", inventory: map[string]*hostInfo{
		"a": {services: []domain.Service{{Host: "a", Port: 445, Protocol: "tcp"}, {Host: "a", Port: 445, Protocol: "udp"}, {Host: "a", Port: 22, Protocol: "tcp"}}},
		"b": {services: []domain.Service{{Host: "b", Port: 445, Protocol: "tcp"}}},
		"c": {services: []domain.Service{{Host: "c", Port: 22, Protocol: "tcp"}}},
	}}
	services, hosts := m.bulkPortServices()
	if len(services) != 2 || strings.Join(hosts, ",") != "a,b" {
		t.Fatalf("filter: %v %v", services, hosts)
	}
	if !strings.Contains(m.selectionScope(), "пропущено 1") {
		t.Fatal("scope does not report skipped hosts")
	}
	m.pendingTemplateIDs = []string{"test.yaml"}
	spec, msg := m.buildSpec(actionRow{kind: jobBulkPort})
	if msg != "" || len(spec.services) != 2 || len(spec.hosts) != 2 || spec.port != 445 {
		t.Fatalf("wrong launch: %+v %s", spec, msg)
	}
}

func TestBulkPortChecksContactOnlySelectedPortOnMatchingHosts(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Host]++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits["wrong-port"]++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer other.Close()
	otherPort := other.Listener.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "nuclei-templates"), 0700); err != nil {
		t.Fatal(err)
	}
	template := "id: bulk-test\ninfo:\n  name: bulk-test\n  severity: info\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/']\n    matchers:\n      - type: status\n        status: [200]\n"
	if err := os.WriteFile(filepath.Join(dir, "nuclei-templates", "test.yaml"), []byte(template), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, err := store.CreateProject(context.Background(), "bulk-port")
	if err != nil {
		t.Fatal(err)
	}
	m := model{ctx: context.Background(), store: store, cat: catalog.NewWithLibrary(dir, dir), scanner: engine.New(store, engine.Config{RPS: 100, Concurrency: 2}), current: domain.Project{ID: id}, bulkPort: port, bulkProtocol: "tcp", actionHosts: []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}, inventory: map[string]*hostInfo{}}
	for _, host := range m.actionHosts {
		services := []domain.Service{{Host: host, Port: otherPort, Protocol: "tcp", Name: "http"}}
		if host != "127.0.0.3" {
			services = append(services, domain.Service{Host: host, Port: port, Protocol: "tcp", Name: "http"})
		}
		m.inventory[host] = &hostInfo{services: services}
	}
	services, _ := m.bulkPortServices()
	result, err := m.runServiceChecks(services, []string{"test.yaml"})(context.Background(), func(string, ...int) {})
	if err != nil || len(result.Errors) != 0 {
		t.Fatalf("scan errors: %v %v", err, result.Errors)
	}
	if len(result.Services) != 2 || len(result.Findings) != 2 {
		t.Fatalf("result escaped scope: %+v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits["wrong-port"] != 0 || len(hits) != 2 {
		t.Fatalf("unexpected requests: %v", hits)
	}
	for _, service := range result.Services {
		if service.Port != port || service.Host == "127.0.0.3" {
			t.Fatalf("wrong service: %+v", service)
		}
	}
}
