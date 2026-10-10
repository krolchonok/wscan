package engine

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestHostKey(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM:8443/path": "example.com",
		"192.168.1.1:80":                "192.168.1.1",
		"Host.Local":                    "host.local",
	}
	for in, want := range cases {
		if got := hostKey(in); got != want {
			t.Errorf("hostKey(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsOverloadErr(t *testing.T) {
	if !isOverloadErr(errors.New("read tcp: connection reset by peer")) {
		t.Fatal("expected reset to be overload")
	}
	if !isOverloadErr(errors.New("i/o timeout")) {
		t.Fatal("expected timeout to be overload")
	}
	if !isOverloadErr(errors.New("dial tcp 10.0.0.10:80: connect: cannot assign requested address")) {
		t.Fatal("expected ephemeral-port exhaustion to be overload")
	}
	if isOverloadErr(errors.New("404 not found")) {
		t.Fatal("application error is not overload")
	}
}

func TestScanHTTPClientCapsConnsPerHost(t *testing.T) {
	c := newScanHTTPClient(5, 12)
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if tr.MaxConnsPerHost != 12 || tr.MaxIdleConnsPerHost != 12 {
		t.Fatalf("MaxConnsPerHost=%d MaxIdle=%d", tr.MaxConnsPerHost, tr.MaxIdleConnsPerHost)
	}
}

func TestHostGateBacksOff(t *testing.T) {
	g := newHostGate(8)
	ctx := context.Background()
	if err := g.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	g.Release("h", true)
	g.Release("h", true) // streak >= 2 → limit halves
	st := g.state("h")
	st.mu.Lock()
	limit := st.limit
	st.mu.Unlock()
	if limit > 4 {
		t.Fatalf("expected limit to shrink after overload, got %d", limit)
	}
	// Acquire should apply delay but still succeed.
	start := time.Now()
	if err := g.Acquire(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	g.Release("h", false)
	if time.Since(start) < 50*time.Millisecond {
		t.Fatalf("expected backoff delay after fail streak, elapsed %s", time.Since(start))
	}
}
