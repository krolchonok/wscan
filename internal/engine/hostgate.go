package engine

import (
	"context"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// hostGate limits concurrent checks per host and backs off when the target
// starts resetting/timing out under load (typical of SOHO routers).
type hostGate struct {
	maxHost int
	mu      sync.Mutex
	states  map[string]*hostState
}

type hostState struct {
	mu         sync.Mutex
	limit      int
	inflight   int
	failStreak int
}

func newHostGate(workers int) *hostGate {
	// Cap per-host concurrency well below typical ephemeral-port budgets.
	// Global workers may be higher (queued); only this many dial at once per host.
	maxHost := workers
	if maxHost > 12 {
		maxHost = 12
	}
	if maxHost < 1 {
		maxHost = 1
	}
	return &hostGate{maxHost: maxHost, states: map[string]*hostState{}}
}

func (g *hostGate) state(host string) *hostState {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.states[host]
	if !ok {
		st = &hostState{limit: g.maxHost}
		g.states[host] = st
	}
	return st
}

// Acquire waits until the host has a free concurrency slot (and applies a short
// delay when the host has recently been overloaded).
func (g *hostGate) Acquire(ctx context.Context, host string) error {
	if host == "" {
		host = "_"
	}
	st := g.state(host)
	for {
		st.mu.Lock()
		if st.inflight < st.limit {
			if st.failStreak >= 2 {
				delay := time.Duration(st.failStreak) * 75 * time.Millisecond
				if delay > 2*time.Second {
					delay = 2 * time.Second
				}
				st.mu.Unlock()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
				}
				st.mu.Lock()
				if st.inflight >= st.limit {
					st.mu.Unlock()
					continue
				}
			}
			st.inflight++
			st.mu.Unlock()
			return nil
		}
		st.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(15 * time.Millisecond):
		}
	}
}

// Release frees a slot. overloaded=true shrinks the host's concurrency ceiling.
func (g *hostGate) Release(host string, overloaded bool) {
	if host == "" {
		host = "_"
	}
	st := g.state(host)
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.inflight > 0 {
		st.inflight--
	}
	if overloaded {
		st.failStreak++
		if st.failStreak >= 2 && st.limit > 1 {
			next := st.limit / 2
			if next < 1 {
				next = 1
			}
			st.limit = next
		}
		return
	}
	st.failStreak = 0
	if st.limit < g.maxHost {
		st.limit++
	}
}

// hostKey extracts a stable host key from a scan target (URL or host[:port]).
func hostKey(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return "_"
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

// isOverloadErr reports transport failures that usually mean the target (or the
// local stack) is saturated, not that the check itself is invalid.
func isOverloadErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, n := range []string{
		"connection reset",
		"broken pipe",
		"i/o timeout",
		"tls handshake timeout",
		"timeout awaiting response",
		"too many open files",
		"no buffer space",
		"resource temporarily unavailable",
		"connection timed out",
		"use of closed network connection",
		"cannot assign requested address", // local ephemeral ports exhausted
		"address already in use",
		"unexpected eof",
		": eof",
	} {
		if strings.Contains(s, n) {
			return true
		}
	}
	return s == "eof"
}

func errorsOverloaded(errs []error) bool {
	for _, err := range errs {
		if isOverloadErr(err) {
			return true
		}
	}
	return false
}
