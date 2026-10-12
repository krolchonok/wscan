package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type Terminal interface {
	Frame() (string, bool)
	Key(string) error
	Resize(int, int)
	Close()
}
type TerminalFactory func(context.Context, int, int) (Terminal, error)
type terminalSession struct {
	terminal Terminal
	lastSeen time.Time
	session  string
	cancel   context.CancelFunc
}
type terminalState struct {
	mu       sync.Mutex
	factory  TerminalFactory
	sessions map[int]*terminalSession
	next     int
}

func (s *Server) EnableTerminal(factory TerminalFactory) {
	s.terminals.mu.Lock()
	defer s.terminals.mu.Unlock()
	s.terminals.factory = factory
}
func (s *Server) terminalRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/terminals", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Width  int `json:"width"`
			Height int `json:"height"`
		}
		if err := decode(w, r, &body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		cookie, _ := r.Cookie("wscan_session")
		state := &s.terminals
		state.mu.Lock()
		defer state.mu.Unlock()
		if state.factory == nil {
			fail(w, 503, "полный TUI недоступен в этом режиме")
			return
		}
		for id, session := range state.sessions {
			if time.Since(session.lastSeen) > 15*time.Minute {
				session.cancel()
				session.terminal.Close()
				delete(state.sessions, id)
			}
		}
		if len(state.sessions) >= 3 {
			fail(w, 409, "закройте неиспользуемый сеанс TUI; максимум три сеанса")
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		terminal, err := state.factory(ctx, body.Width, body.Height)
		if err != nil {
			cancel()
			fail(w, 500, err.Error())
			return
		}
		state.next++
		id := state.next
		if state.sessions == nil {
			state.sessions = map[int]*terminalSession{}
		}
		state.sessions[id] = &terminalSession{terminal: terminal, lastSeen: time.Now(), session: cookie.Value, cancel: cancel}
		writeJSON(w, 201, map[string]int{"id": id})
	})
	mux.HandleFunc("GET /api/terminals/{terminal}", func(w http.ResponseWriter, r *http.Request) {
		session, err := s.terminal(r)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		frame, closed := session.terminal.Frame()
		writeJSON(w, 200, map[string]any{"frame": frame, "closed": closed})
	})
	mux.HandleFunc("POST /api/terminals/{terminal}/key", func(w http.ResponseWriter, r *http.Request) {
		session, err := s.terminal(r)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		var body struct {
			Key string `json:"key"`
		}
		if err := decode(w, r, &body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if err := session.terminal.Key(body.Key); err != nil {
			fail(w, 409, err.Error())
			return
		}
		writeJSON(w, 200, map[string]bool{"sent": true})
	})
	mux.HandleFunc("POST /api/terminals/{terminal}/resize", func(w http.ResponseWriter, r *http.Request) {
		session, err := s.terminal(r)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		var body struct {
			Width  int `json:"width"`
			Height int `json:"height"`
		}
		if err := decode(w, r, &body); err != nil {
			fail(w, 400, err.Error())
			return
		}
		session.terminal.Resize(body.Width, body.Height)
		writeJSON(w, 200, map[string]bool{"resized": true})
	})
	mux.HandleFunc("DELETE /api/terminals/{terminal}", func(w http.ResponseWriter, r *http.Request) {
		session, err := s.terminal(r)
		if err != nil {
			fail(w, 404, err.Error())
			return
		}
		session.cancel()
		session.terminal.Close()
		id, _ := strconv.Atoi(r.PathValue("terminal"))
		s.terminals.mu.Lock()
		delete(s.terminals.sessions, id)
		s.terminals.mu.Unlock()
		writeJSON(w, 200, map[string]bool{"closed": true})
	})
}
func (s *Server) terminal(r *http.Request) (*terminalSession, error) {
	id, _ := strconv.Atoi(r.PathValue("terminal"))
	cookie, _ := r.Cookie("wscan_session")
	s.terminals.mu.Lock()
	defer s.terminals.mu.Unlock()
	session, ok := s.terminals.sessions[id]
	if !ok || cookie == nil || session.session != cookie.Value {
		return nil, fmt.Errorf("сеанс TUI не найден")
	}
	session.lastSeen = time.Now()
	return session, nil
}
func (s *Server) closeTerminals() {
	s.terminals.mu.Lock()
	defer s.terminals.mu.Unlock()
	for id, session := range s.terminals.sessions {
		session.cancel()
		session.terminal.Close()
		delete(s.terminals.sessions, id)
	}
}
