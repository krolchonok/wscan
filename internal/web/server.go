// Package web is the local HTTP transport for the shared application service.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"wscan/internal/app"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/report"
)

//go:embed assets/*
var assets embed.FS

type Server struct {
	terminals terminalState
	done      chan struct{}
	stopOnce  sync.Once
	App       *app.Service
	Host      string
	mu        sync.Mutex
	bootstrap string
	used      bool
	sessions  map[string]string
	HTTP      *http.Server
	Listener  net.Listener
}

func secret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func New(service *app.Service, host string) *Server {
	return &Server{done: make(chan struct{}), App: service, Host: host, bootstrap: secret(), sessions: map[string]string{}}
}
func (s *Server) URL() string { return "http://" + s.Host + "/#token=" + s.bootstrap }
func Start(service *app.Service, address string) (*Server, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("--listen: IP:порт")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("локальный Web слушает только loopback IP (например 127.0.0.1:8080)")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	s := New(service, listener.Addr().String())
	s.Listener = listener
	s.HTTP = &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	go func() { _ = s.HTTP.Serve(listener) }()
	return s, nil
}
func (s *Server) Close(ctx context.Context) error {
	if s.HTTP == nil {
		return nil
	}
	s.stopOnce.Do(func() { close(s.done); s.closeTerminals() })
	err := s.HTTP.Shutdown(ctx)
	if err != nil {
		_ = s.HTTP.Close()
	}
	return err
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, value any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return fmt.Errorf("ожидается application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return fmt.Errorf("некорректный JSON: %w", err)
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("ожидается один JSON-объект")
	}
	return nil
}
func (s *Server) auth(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("wscan_session")
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	csrf, ok := s.sessions[cookie.Value]
	return csrf, ok
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.terminalRoutes(mux)
	mux.HandleFunc("POST /api/session", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		if err := decode(w, r, &body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.used || subtle.ConstantTimeCompare([]byte(body.Token), []byte(s.bootstrap)) != 1 {
			fail(w, 401, "ссылка подключения недействительна; используйте уже подключённый браузер или перезапустите Web")
			return
		}
		s.used = true
		session, csrf := secret(), secret()
		s.sessions[session] = csrf
		http.SetCookie(w, &http.Cookie{Name: "wscan_session", Value: session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, 200, map[string]string{"csrf": csrf})
	})
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		csrf, ok := s.auth(r)
		if !ok {
			fail(w, 401, "откройте ссылку Web из терминала")
			return
		}
		writeJSON(w, 200, map[string]string{"csrf": csrf})
	})
	mux.HandleFunc("GET /api/projects", func(w http.ResponseWriter, r *http.Request) {
		ps, err := s.App.Store.ListProjects(r.Context())
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		if ps == nil {
			ps = []domain.Project{}
		}
		writeJSON(w, 200, ps)
	})
	mux.HandleFunc("POST /api/projects", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name    string   `json:"name"`
			Targets []string `json:"targets"`
		}
		if err := decode(w, r, &body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		id, err := s.App.CreateProject(r.Context(), body.Name, body.Targets)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		writeJSON(w, 201, map[string]int64{"id": id})
	})
	mux.HandleFunc("GET /api/projects/{project}", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.project(r)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("DELETE /api/projects/{project}", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.project(r)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		if err := s.App.DeleteProject(r.Context(), p.ID); err != nil {
			fail(w, 409, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"deleted": true})
	})
	mux.HandleFunc("PUT /api/projects/{project}/settings", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.project(r)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		var body domain.Project
		if err := decode(w, r, &body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		body.ID = p.ID
		if err := s.App.SaveSettings(r.Context(), body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"saved": true})
	})
	mux.HandleFunc("POST /api/projects/{project}/targets", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.project(r)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		var body struct {
			Target string `json:"target"`
		}
		if err := decode(w, r, &body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if _, err := s.App.ValidateTargets([]string{body.Target}); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if err := s.App.Store.AddTarget(r.Context(), p.ID, body.Target); err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"saved": true})
	})
	mux.HandleFunc("GET /api/projects/{project}/inventory", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.project(r)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		inventory, err := s.App.Inventory(r.Context(), p.ID)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, inventory)
	})
	mux.HandleFunc("GET /api/projects/{project}/credentials", s.credentials)
	mux.HandleFunc("POST /api/projects/{project}/credentials", s.credentials)
	mux.HandleFunc("DELETE /api/projects/{project}/credentials/{credential}", s.credentials)
	mux.HandleFunc("GET /api/jobs", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, s.App.Jobs.List()) })
	mux.HandleFunc("POST /api/jobs", func(w http.ResponseWriter, r *http.Request) {
		var body app.ScanRequest
		if err := decode(w, r, &body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		j, err := s.App.StartScan(r.Context(), body, "web", r.Header.Get("Idempotency-Key"))
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		writeJSON(w, 201, j)
	})
	mux.HandleFunc("GET /api/jobs/{job}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.PathValue("job"))
		j, ok := s.App.Jobs.Get(id)
		if !ok {
			fail(w, 404, "задача не найдена")
			return
		}
		writeJSON(w, 200, j)
	})
	mux.HandleFunc("POST /api/jobs/{job}/cancel", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.PathValue("job"))
		if err := s.App.Jobs.Cancel(id); err != nil {
			fail(w, 404, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"cancelled": true})
	})
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/catalog", func(w http.ResponseWriter, r *http.Request) {
		entries, err := s.App.Entries()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		q := strings.ToLower(r.URL.Query().Get("q"))
		var out []any
		for _, e := range entries {
			if q == "" || strings.Contains(strings.ToLower(e.Path+" "+e.SearchText), q) {
				out = append(out, e)
				if len(out) >= 200 {
					break
				}
			}
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("GET /api/modules", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, engine.AvailableModules(r.URL.Query().Get("protocol")))
	})
	mux.HandleFunc("POST /api/modules", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ProjectID    int64             `json:"project_id"`
			CredentialID int64             `json:"credential_id"`
			Target       domain.Service    `json:"target"`
			Name         string            `json:"name"`
			Args         map[string]string `json:"args"`
		}
		if err := decode(w, r, &body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		j, err := s.App.StartModule(r.Context(), body.ProjectID, body.CredentialID, body.Target, body.Name, body.Args, "web", r.Header.Get("Idempotency-Key"))
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		writeJSON(w, 201, j)
	})
	mux.HandleFunc("GET /api/projects/{project}/runs/{run}/export", s.export)
	mux.HandleFunc("PUT /api/projects/{project}/templates", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.project(r)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		var body struct {
			IDs []string `json:"ids"`
		}
		if err := decode(w, r, &body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		entries, err := s.App.Entries()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		known := map[string]bool{}
		for _, e := range entries {
			known[e.Path] = true
		}
		for _, id := range body.IDs {
			if !known[id] {
				fail(w, 400, "проверка отсутствует в каталоге")
				return
			}
		}
		if err := s.App.Store.SetTemplates(r.Context(), p.ID, p.TemplateIDs, false); err != nil {
			fail(w, 500, err.Error())
			return
		}
		if err := s.App.Store.SetTemplates(r.Context(), p.ID, body.IDs, true); err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"saved": true})
	})
	static, _ := fs.Sub(assets, "assets")
	mux.Handle("/", http.FileServer(http.FS(static)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if r.Host != s.Host {
			fail(w, 403, "неверный адрес Web-сервера")
			return
		}
		origin := r.Header.Get("Origin")
		expected := "http://" + s.Host
		if origin != "" && origin != expected {
			fail(w, 403, "запрос из другого сайта отклонён")
			return
		}
		mutating := r.Method != "GET" && r.Method != "HEAD"
		if mutating && origin != expected {
			fail(w, 403, "Origin обязателен")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/session" {
			csrf, ok := s.auth(r)
			if !ok {
				fail(w, 401, "откройте ссылку Web из терминала")
				return
			}
			if mutating && subtle.ConstantTimeCompare([]byte(csrf), []byte(r.Header.Get("X-Wscan-CSRF"))) != 1 {
				fail(w, 403, "проверка сессии не пройдена")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func (s *Server) project(r *http.Request) (domain.Project, error) {
	id, err := strconv.ParseInt(r.PathValue("project"), 10, 64)
	if err != nil || id < 1 {
		return domain.Project{}, fmt.Errorf("проект не найден")
	}
	return s.App.Project(r.Context(), id)
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		fail(w, 500, "поток событий недоступен")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var revision uint64
	for {
		jobs := s.App.Jobs.List()
		var current uint64
		for _, j := range jobs {
			current = max(current, j.Revision)
		}
		if revision == 0 || current != revision {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
			raw, _ := json.Marshal(jobs)
			if _, err := fmt.Fprintf(w, "id: %d\nevent: jobs\ndata: %s\n\n", current, raw); err != nil {
				return
			}
			f.Flush()
			revision = current
		}
		select {
		case <-s.done:
			return
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Server) credentials(w http.ResponseWriter, r *http.Request) {
	p, err := s.project(r)
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	creds, err := s.App.Store.ListCredentials(r.Context(), p.ID)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	switch r.Method {
	case "GET":
		out := []map[string]any{}
		for _, c := range creds {
			out = append(out, map[string]any{"id": c.ID, "username": c.Username, "domain": c.Domain, "type": c.Type, "notes": c.Notes})
		}
		writeJSON(w, 200, out)
	case "POST":
		var c domain.Credential
		if err := decode(w, r, &c); err != nil {
			fail(w, 400, err.Error())
			return
		}
		c.ID = 0
		c.ProjectID = p.ID
		if c.Type != "password" && c.Type != "ntlm-hash" {
			fail(w, 400, "тип: password или ntlm-hash")
			return
		}
		id, err := s.App.Store.CreateCredential(r.Context(), c)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		writeJSON(w, 201, map[string]int64{"id": id})
	case "DELETE":
		id, _ := strconv.ParseInt(r.PathValue("credential"), 10, 64)
		found := false
		for _, c := range creds {
			if c.ID == id {
				found = true
			}
		}
		if !found {
			fail(w, 404, "учётка не принадлежит проекту")
			return
		}
		if err := s.App.Store.DeleteCredential(r.Context(), id); err != nil {
			fail(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"deleted": true})
	}
}
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	p, err := s.project(r)
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("run"), 10, 64)
	runs, err := s.App.Store.Runs(r.Context(), p.ID)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	for _, run := range runs {
		if run.ID == id {
			format := r.URL.Query().Get("format")
			if format == "" {
				format = "json"
			}
			contentType := map[string]string{"json": "application/json", "html": "text/html; charset=utf-8", "csv": "text/csv; charset=utf-8"}[format]
			if contentType == "" {
				fail(w, 400, "формат: json, html или csv")
				return
			}
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=wscan-run-%d.%s", id, format))
			w.Header().Set("Content-Type", contentType)
			_ = report.Write(w, format, report.Data{Project: p.Name, Run: run})
			return
		}
	}
	fail(w, 404, "запуск не принадлежит проекту")
}
