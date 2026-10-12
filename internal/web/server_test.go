package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wscan/internal/app"
	"wscan/internal/catalog"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/storage"
)

type webFixture struct {
	server *Server
	http   *httptest.Server
	client *http.Client
	csrf   string
}

func newWebFixture(t *testing.T) *webFixture {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := app.NewService(context.Background(), store, catalog.NewWithLibrary(dir, ""), engine.New(store, engine.Config{TimeoutSeconds: 1}))
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewUnstartedServer(nil)
	s := New(service, h.Listener.Addr().String())
	h.Config.Handler = s.Handler()
	h.Start()
	jar, _ := cookiejar.New(nil)
	f := &webFixture{server: s, http: h, client: &http.Client{Jar: jar}}
	t.Cleanup(func() { h.Close(); service.Close(); store.Close() })
	r := f.request(t, "POST", "/api/session", map[string]string{"token": s.bootstrap})
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("login: %d", r.StatusCode)
	}
	var response map[string]string
	json.NewDecoder(r.Body).Decode(&response)
	f.csrf = response["csrf"]
	return f
}
func (f *webFixture) request(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	r, _ := http.NewRequest(method, f.http.URL+path, bytes.NewReader(data))
	r.Header.Set("Origin", f.http.URL)
	r.Header.Set("X-Wscan-CSRF", f.csrf)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func TestWebAuthOriginCSRFAndSecretMasking(t *testing.T) {
	f := newWebFixture(t)
	raw, err := http.Get(f.http.URL + "/api/projects")
	if err != nil {
		t.Fatal(err)
	}
	raw.Body.Close()
	if raw.StatusCode != 401 {
		t.Fatal("unauthenticated API allowed")
	}
	for _, modify := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }, func(r *http.Request) { r.Header.Del("X-Wscan-CSRF") }, func(r *http.Request) { r.Host = "evil.example" }} {
		req, _ := http.NewRequest("POST", f.http.URL+"/api/projects", strings.NewReader(`{"name":"forbidden"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", f.http.URL)
		req.Header.Set("X-Wscan-CSRF", f.csrf)
		modify(req)
		r, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 403 {
			t.Fatalf("request bypassed protection: %d", r.StatusCode)
		}
	}
	r := f.request(t, "POST", "/api/projects", map[string]any{"name": "fixture", "targets": []string{"127.0.0.1"}})
	var created map[string]int64
	json.NewDecoder(r.Body).Decode(&created)
	r.Body.Close()
	if r.StatusCode != 201 {
		t.Fatal("create project")
	}
	id := created["id"]
	_, err = f.server.App.Store.CreateCredential(context.Background(), domain.Credential{ProjectID: id, Type: "password", Username: "reader", Secret: "do-not-return-this"})
	if err != nil {
		t.Fatal(err)
	}
	r = f.request(t, "GET", "/api/projects/1/credentials", nil)
	data, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if strings.Contains(string(data), "do-not-return-this") || strings.Contains(string(data), "Secret") {
		t.Fatalf("secret exposed: %s", data)
	}
	r = f.request(t, "POST", "/api/session", map[string]string{"token": f.server.bootstrap})
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatal("one-time bootstrap reused")
	}
}
func TestWebCancelsExistingSharedTaskAndStreamsSnapshot(t *testing.T) {
	f := newWebFixture(t)
	ctx := context.Background()
	id, _ := f.server.App.CreateProject(ctx, "fixture", []string{"127.0.0.1"})
	job, err := f.server.App.Jobs.Start(app.JobRequest{ProjectID: id, Source: "tui", Kind: "fixture", Label: "shared"}, "", func(ctx context.Context, emit app.Reporter) (app.Outcome, error) {
		emit("Ожидание", 1, 2)
		<-ctx.Done()
		return app.Outcome{}, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	r := f.request(t, "GET", "/api/jobs", nil)
	var jobs []app.Job
	json.NewDecoder(r.Body).Decode(&jobs)
	r.Body.Close()
	if len(jobs) != 1 || jobs[0].ID != job.ID {
		t.Fatal("TUI job invisible in Web")
	}
	stream := f.request(t, "GET", "/api/events", nil)
	buf := make([]byte, 4096)
	n, err := stream.Body.Read(buf)
	stream.Body.Close()
	if err != nil || !strings.Contains(string(buf[:n]), "shared") {
		t.Fatalf("event snapshot: %v %s", err, buf[:n])
	}
	r = f.request(t, "POST", "/api/jobs/1/cancel", nil)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("cancel failed")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		j, _ := f.server.App.Jobs.Get(job.ID)
		if j.Status == "cancelled" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("web cancellation did not stop shared executor")
}
func TestWebRejectsForeignCredentialAndRun(t *testing.T) {
	f := newWebFixture(t)
	ctx := context.Background()
	one, _ := f.server.App.CreateProject(ctx, "one", nil)
	two, _ := f.server.App.CreateProject(ctx, "two", nil)
	cid, _ := f.server.App.Store.CreateCredential(ctx, domain.Credential{ProjectID: two, Type: "password", Secret: "private"})
	run, _ := f.server.App.Store.StartRun(ctx, two)
	if one != 1 || cid != 1 || run != 1 {
		t.Fatal("fixture IDs changed")
	}
	for _, path := range []string{"/api/projects/1/credentials/1", "/api/projects/1/runs/1/export"} {
		method := "GET"
		if strings.Contains(path, "credentials") {
			method = "DELETE"
		}
		r := f.request(t, method, path, nil)
		r.Body.Close()
		if r.StatusCode != 404 {
			t.Fatalf("cross-project action allowed: %s %d", path, r.StatusCode)
		}
	}
}
