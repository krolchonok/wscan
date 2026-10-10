package engine

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"testing"
	"time"

	"wscan/internal/domain"

	realssh "golang.org/x/crypto/ssh"
)

// fakePasswordSSHServer is a standard golang.org/x/crypto/ssh server (SSH is
// a wire protocol — which Go implementation sits on each end doesn't matter)
// that accepts exactly one username/password pair. Mirrors
// internal/engine/js/ssh_test.go's helper of the same shape.
func fakePasswordSSHServer(t *testing.T, user, pass string) int {
	return callbackPasswordSSHServer(t, func(conn realssh.ConnMetadata, password []byte) (*realssh.Permissions, error) {
		if conn.User() == user && string(password) == pass {
			return &realssh.Permissions{}, nil
		}
		return nil, errors.New("wrong credentials")
	})
}
func callbackPasswordSSHServer(t *testing.T, callback func(realssh.ConnMetadata, []byte) (*realssh.Permissions, error)) int {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := realssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &realssh.ServerConfig{PasswordCallback: callback}
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				conn, chans, reqs, err := realssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go realssh.DiscardRequests(reqs)
				for newChan := range chans {
					_ = newChan.Reject(realssh.Prohibited, "no channels")
				}
			}(nConn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestSprayCredentialsRefusedWithoutAllowCredentialAttack(t *testing.T) {
	e := New(&fakeStore{}, Config{TimeoutSeconds: 5})
	_, err := e.SprayCredentials(context.Background(), domain.Project{ID: 1}, nil, nil)
	if err == nil {
		t.Fatal("expected an error when AllowCredentialAttack is false")
	}
}

// TestSprayCredentialsSkipsAfterLockoutThreshold is the core safety property
// from this session's requirement: once a username's recorded failures hit
// the project's threshold, the engine must refuse to send the attempt at
// all — not just log a warning — and must not record an additional failure
// for an attempt that was never sent.
func TestSprayCredentialsSkipsAfterLockoutThreshold(t *testing.T) {
	store := &fakeStore{failureCounts: map[string]int{"jdoe": 3}}
	e := New(store, Config{TimeoutSeconds: 5})
	p := domain.Project{ID: 1, AllowCredentialAttack: true, LockoutMaxAttempts: 3, LockoutWindowMinutes: 30}
	targets := []domain.Service{{Host: "127.0.0.1", Port: 1, Protocol: "ssh"}}
	creds := []domain.Credential{{Username: "jdoe", Secret: "x"}}

	res, err := e.SprayCredentials(context.Background(), p, targets, creds)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Attempts) != 1 {
		t.Fatalf("expected 1 attempt record, got %d", len(res.Attempts))
	}
	if !res.Attempts[0].Skipped {
		t.Fatalf("expected the attempt to be skipped once the lockout threshold is reached, got %+v", res.Attempts[0])
	}
	if store.failureCounts["jdoe"] != 3 {
		t.Fatalf("a skipped attempt must not record an additional failure, got count %d", store.failureCounts["jdoe"])
	}
}

// TestSprayCredentialsUsesConservativeDefaultWhenUnset reproduces the "zero
// means default, not unlimited" contract: a project that never configured
// LockoutMaxAttempts must still stop spraying a username once
// domain.DefaultLockoutMaxAttempts failures have been recorded.
func TestSprayCredentialsUsesConservativeDefaultWhenUnset(t *testing.T) {
	store := &fakeStore{failureCounts: map[string]int{"jdoe": domain.DefaultLockoutMaxAttempts}}
	e := New(store, Config{TimeoutSeconds: 5})
	p := domain.Project{ID: 1, AllowCredentialAttack: true} // LockoutMaxAttempts/Window left at zero
	targets := []domain.Service{{Host: "127.0.0.1", Port: 1, Protocol: "ssh"}}
	creds := []domain.Credential{{Username: "jdoe", Secret: "x"}}

	res, err := e.SprayCredentials(context.Background(), p, targets, creds)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Attempts[0].Skipped {
		t.Fatalf("expected the default lockout threshold to apply when unset, got %+v", res.Attempts[0])
	}
}

func TestSprayCredentialsDispatchesAndRecordsFailureForUnsupportedProtocol(t *testing.T) {
	store := &fakeStore{}
	e := New(store, Config{TimeoutSeconds: 1})
	p := domain.Project{ID: 1, AllowCredentialAttack: true}
	targets := []domain.Service{{Host: "127.0.0.1", Port: 1, Protocol: "carrier-pigeon"}}
	creds := []domain.Credential{{Username: "jdoe", Secret: "x"}}

	res, err := e.SprayCredentials(context.Background(), p, targets, creds)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Attempts) != 1 || res.Attempts[0].Success || res.Attempts[0].Skipped {
		t.Fatalf("expected one failed, non-skipped attempt, got %+v", res.Attempts)
	}
	if res.Attempts[0].Error == "" {
		t.Fatal("expected an error message naming the unsupported protocol")
	}
	if store.failureCounts["jdoe"] != 1 {
		t.Fatalf("a dispatched failed attempt must be recorded, got count %d", store.failureCounts["jdoe"])
	}
}

// TestSprayCredentialsDispatchesLDAPAndWinRM locks in that the ldap/ldaps/
// winrm protocol names added in Phase 3 actually reach their respective
// clients (a real dial/auth error against a closed port, not "unsupported
// protocol") — the dispatcher-level counterpart to each client's own unit
// tests in internal/engine/js.
func TestSprayCredentialsDispatchesLDAPAndWinRM(t *testing.T) {
	for _, protocol := range []string{"ldap", "ldaps", "winrm"} {
		store := &fakeStore{}
		e := New(store, Config{TimeoutSeconds: 1})
		p := domain.Project{ID: 1, AllowCredentialAttack: true}
		targets := []domain.Service{{Host: "127.0.0.1", Port: 1, Protocol: protocol}}
		creds := []domain.Credential{{Username: "jdoe", Domain: "CORP", Secret: "x"}}

		res, err := e.SprayCredentials(context.Background(), p, targets, creds)
		if err != nil {
			t.Fatalf("%s: %v", protocol, err)
		}
		if len(res.Attempts) != 1 || res.Attempts[0].Success {
			t.Fatalf("%s: expected one failed attempt, got %+v", protocol, res.Attempts)
		}
		if res.Attempts[0].Error == "" {
			t.Fatalf("%s: expected a real dial/auth error", protocol)
		}
		if res.Attempts[0].Error == `credential spray: unsupported protocol "`+protocol+`"` {
			t.Fatalf("%s: protocol must be dispatched to its client, not rejected as unsupported", protocol)
		}
	}
}

// TestSprayCredentialsEndToEndAgainstRealSSHServer exercises the full path —
// dispatch through tryLogin's real SSH client, not just the bookkeeping —
// with both a correct and a wrong credential against the same fake server.
func TestSprayCredentialsEndToEndAgainstRealSSHServer(t *testing.T) {
	port := fakePasswordSSHServer(t, "admin", "correct-horse")
	store := &fakeStore{}
	e := New(store, Config{TimeoutSeconds: 5})
	p := domain.Project{ID: 1, AllowCredentialAttack: true}
	targets := []domain.Service{{Host: "127.0.0.1", Port: port, Protocol: "ssh"}}
	creds := []domain.Credential{
		{Username: "admin", Secret: "wrong-guess"},
		{Username: "admin", Secret: "correct-horse"},
	}

	res, err := e.SprayCredentials(context.Background(), p, targets, creds)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(res.Attempts))
	}
	if res.Attempts[0].Success {
		t.Fatalf("wrong password must not report success: %+v", res.Attempts[0])
	}
	if !res.Attempts[1].Success {
		t.Fatalf("correct password must report success: %+v", res.Attempts[1])
	}
}

func TestSprayTelnetDiscoveredTCPService(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				r := bufio.NewReader(c)
				c.Write([]byte("login:"))
				u, err := r.ReadString('\n')
				if err != nil {
					return
				}
				c.Write([]byte("Password:"))
				p, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if u == "root\r\n" && p == "root\r\n" {
					c.Write([]byte("\r\nroot@host:~#"))
				} else {
					c.Write([]byte("\r\nLogin incorrect"))
				}
			}()
		}
	}()
	e := New(&fakeStore{}, Config{TimeoutSeconds: 1})
	res, err := e.SprayCredentials(context.Background(), domain.Project{ID: 1, AllowCredentialAttack: true}, []domain.Service{{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Protocol: "tcp", Name: "telnet"}}, []domain.Credential{{Type: "password", Username: "root", Secret: "root"}, {Type: "password", Username: "root", Secret: "wrong"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Attempts) != 2 || !res.Attempts[0].Success || res.Attempts[1].Success || res.Attempts[1].Error != "" || res.Attempts[0].Protocol != "telnet" {
		t.Fatalf("attempts=%+v", res.Attempts)
	}
}
