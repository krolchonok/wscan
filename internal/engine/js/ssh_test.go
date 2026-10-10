package js

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"testing"
	"time"

	realssh "golang.org/x/crypto/ssh"
)

func mustTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// fakePasswordSSHServer is a standard golang.org/x/crypto/ssh server (SSH is
// a wire protocol — which Go implementation sits on each end doesn't matter)
// that accepts one specific username/password pair.
func fakePasswordSSHServer(t *testing.T, user, pass string) int {
	t.Helper()
	hostKey, err := realssh.NewSignerFromKey(mustTestRSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &realssh.ServerConfig{
		PasswordCallback: func(conn realssh.ConnMetadata, password []byte) (*realssh.Permissions, error) {
			if conn.User() == user && string(password) == pass {
				return &realssh.Permissions{}, nil
			}
			return nil, errors.New("wrong credentials")
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

// TestSSHConnectPasswordWorksViaZgrab2Client pins the zgrab2/lib/ssh
// migration (internal/engine/js/ssh.go) for the password-auth path used by
// ssh-default-logins.yaml / CVE-2020-4429.yaml — those failed against a real
// Win32-OpenSSH target with "ssh: unexpected message type 51 (expected 60)"
// under golang.org/x/crypto/ssh. This confirms the ordinary, protocol-clean
// case still authenticates correctly after switching clients.
func TestSSHConnectPasswordWorksViaZgrab2Client(t *testing.T) {
	port := fakePasswordSSHServer(t, "root", "hunter2")
	c := &SSHClient{ctx: context.Background(), timeout: 5 * time.Second}
	ok, err := c.Connect("127.0.0.1", port, "root", "hunter2")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true for correct credentials")
	}
	defer c.Close()
}

// Negative: wrong credentials must fail cleanly (no panic, no "unexpected
// message type"), matching what ssh-default-logins.yaml's per-attempt
// matcher expects for a non-match.
func TestSSHConnectPasswordRejectsWrongCreds(t *testing.T) {
	port := fakePasswordSSHServer(t, "root", "hunter2")
	c := &SSHClient{ctx: context.Background(), timeout: 5 * time.Second}
	ok, err := c.Connect("127.0.0.1", port, "root", "wrongpass")
	if err == nil {
		t.Fatal("expected an error for wrong credentials")
	}
	if ok {
		t.Fatal("expected ok=false for wrong credentials")
	}
}

// TestConnectSSHInfoModePopulatesServerKex reproduces CVE-2023-48795.yaml's
// (Terrapin attack) "TypeError: Cannot read property 'CiphersClientServer'
// of undefined" — ServerKex was entirely absent from HandshakeInfo, so every
// run crashed before SupportsChaCha20/SupportsCbcEtm/SupportsStrictKex could
// even inspect the negotiated algorithms, on every target regardless of
// whether it was actually vulnerable. zgrab2's own handshake populates
// ConnLog.ServerKex as a side effect of the KEX exchange itself, before user
// auth — confirmed here by using the fake server's default x/crypto/ssh
// algorithm set and checking the exact fields the template reads are
// present and non-empty.
func TestConnectSSHInfoModePopulatesServerKex(t *testing.T) {
	port := fakePasswordSSHServer(t, "root", "hunter2")
	c := &SSHClient{ctx: context.Background(), timeout: 5 * time.Second}
	info, err := c.ConnectSSHInfoMode("127.0.0.1", port)
	if err != nil {
		t.Fatalf("ConnectSSHInfoMode: %v", err)
	}
	if info.ServerKex == nil {
		t.Fatal("ServerKex is nil, want populated kex info")
	}
	if len(info.ServerKex.KexAlgos) == 0 {
		t.Error("KexAlgos is empty")
	}
	if len(info.ServerKex.CiphersClientServer) == 0 {
		t.Error("CiphersClientServer is empty")
	}
	if len(info.ServerKex.CiphersServerClient) == 0 {
		t.Error("CiphersServerClient is empty")
	}
	if len(info.ServerKex.MACsClientServer) == 0 {
		t.Error("MACsClientServer is empty")
	}
	if len(info.ServerKex.MACsServerClient) == 0 {
		t.Error("MACsServerClient is empty")
	}
}
