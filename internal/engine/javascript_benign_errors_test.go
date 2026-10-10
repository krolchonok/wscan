package engine

import (
	"context"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"

	"wscan/internal/domain"
)

// fakeSSHPasswordServer accepts exactly one username/password pair.
func fakeSSHPasswordServer(t *testing.T, user, pass string) int {
	t.Helper()
	hostKey, err := ssh.NewSignerFromKey(mustGenerateRSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == user && string(password) == pass {
				return &ssh.Permissions{}, nil
			}
			return nil, errAuthFailed
		},
	}
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
				conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					_ = newChan.Reject(ssh.Prohibited, "no channels")
				}
			}(nConn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

var errAuthFailed = &authFailedErr{}

type authFailedErr struct{}

func (e *authFailedErr) Error() string { return "wrong credentials" }

// TestSSHDefaultLoginsWrongPasswordIsQuietNotAnError reproduces the real
// run's "Ошибка проверки: ssh-default-logins: javascript: GoError: ssh:
// handshake failed: ssh: unable to authenticate, ... no supported methods
// remain" — that message is the clean, correct rejection of a wrong
// password (the ssh-default-logins.yaml template doesn't try/catch it, same
// as real nuclei). It must no longer surface as a check error: a wrong
// guess out of 223 is not a problem with the scanner.
func TestSSHDefaultLoginsWrongPasswordIsQuietNotAnError(t *testing.T) {
	port := fakeSSHPasswordServer(t, "root", "correct-horse-battery-staple")
	tmpl := loadUpstreamJSTemplate(t, "default-logins", "ssh-default-logins.yaml")
	tmpl = withJSPort(tmpl, port)
	// Pin the payload set to exactly one, deliberately wrong, combo — this
	// is the generic.yaml wordlist filtered down to one guaranteed-to-fail
	// attempt, isolating the "wrong password" case from the real
	// wordlist's unrelated size/content.
	for i := range tmpl.JavaScript {
		tmpl.JavaScript[i].Payloads = domain.PayloadSet{
			"usernames": domain.Payload{Values: []string{"root"}},
			"passwords": domain.Payload{Values: []string{"definitely-wrong"}},
		}
	}

	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 10})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"127.0.0.1"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("wrong password must not surface as a check error, got: %v", res.Errors)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("wrong password must not match, got %d findings", len(res.Findings))
	}
}

// A genuinely unrelated failure (nothing listening) must still be reported
// — isBenignAuthRejection must not swallow real problems.
func TestSSHDefaultLoginsConnectionRefusedStillErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listening now

	tmpl := loadUpstreamJSTemplate(t, "default-logins", "ssh-default-logins.yaml")
	tmpl = withJSPort(tmpl, port)
	for i := range tmpl.JavaScript {
		tmpl.JavaScript[i].PreCondition = "" // force the attempt past the closed-port precondition
		tmpl.JavaScript[i].Payloads = domain.PayloadSet{
			"usernames": domain.Payload{Values: []string{"root"}},
			"passwords": domain.Payload{Values: []string{"x"}},
		}
	}

	e := New(&fakeStore{}, Config{RPS: 100, Concurrency: 4, TimeoutSeconds: 5})
	res, err := e.Scan(context.Background(), domain.Project{ID: 1, Targets: []string{"127.0.0.1"}}, []domain.Template{tmpl})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Errors) == 0 {
		t.Fatal("connection refused is a real problem and must still be reported")
	}
}
