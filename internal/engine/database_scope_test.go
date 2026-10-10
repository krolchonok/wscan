package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"wscan/internal/domain"
)

func TestDatabaseChecksDispatchPerTarget(t *testing.T) {
	var mu sync.Mutex
	hits := map[string][]string{}
	server := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits[name] = append(hits[name], r.URL.Path)
			mu.Unlock()
			w.WriteHeader(200)
		}))
	}
	redis, mysql := server("redis"), server("mysql")
	defer redis.Close()
	defer mysql.Close()
	service := func(raw, name string) domain.Service {
		u, _ := url.Parse(raw)
		port, _ := strconv.Atoi(u.Port())
		return domain.Service{Host: u.Hostname(), Port: port, Name: name, Protocol: "tcp"}
	}
	var templates []domain.Template
	for _, name := range []string{"redis", "mysql"} {
		tm := domain.Template{ID: name + "-detect", Compatible: true}
		tm.Info.Name = name
		tm.Info.Severity = "info"
		tm.HTTP = []domain.HTTPRequest{{Method: "GET", Path: domain.StringList{"{{BaseURL}}/" + name}, Matchers: []domain.Matcher{{Type: "status", Status: []int{200}}}}}
		templates = append(templates, tm)
	}
	p := domain.Project{UseDiscoveredTargets: true, ScanTargets: []string{redis.URL, mysql.URL}, Services: []domain.Service{service(redis.URL, "redis"), service(mysql.URL, "mysql")}, RPS: 100, Concurrency: 1}
	var done, total int
	result, err := New(&fakeStore{}, Config{RPS: 100, Concurrency: 1, TimeoutSeconds: 2}).ScanProgress(context.Background(), p, templates, func(d, t int) { done, total = d, t })
	if err != nil || len(result.Errors) != 0 || len(result.Findings) != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(hits["redis"]) != 1 || hits["redis"][0] != "/redis" || len(hits["mysql"]) != 1 || hits["mysql"][0] != "/mysql" {
		t.Fatalf("wrong DB contacted: %v", hits)
	}
	if done != 2 || total != 2 {
		t.Fatalf("progress=%d/%d", done, total)
	}
}
