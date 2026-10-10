package js

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	realssh "golang.org/x/crypto/ssh"
)

func TestSSHInfoSharesHandshakeAndDoesNotTryPasswords(t *testing.T) {
	var connections, passwordAttempts atomic.Int64
	signer, err := realssh.NewSignerFromKey(mustTestRSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	config := &realssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_9.2p1 test",
		PasswordCallback: func(realssh.ConnMetadata, []byte) (*realssh.Permissions, error) {
			passwordAttempts.Add(1)
			return nil, errors.New("must not try a password during enumeration")
		},
	}
	config.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() { defer conn.Close(); _, _, _, _ = realssh.NewServerConn(conn, config) }()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	ctx := WithSSHInfoCache(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := NewSSHClient(ctx, time.Second)
			info, err := client.ConnectSSHInfoMode("127.0.0.1", port)
			if err != nil {
				t.Error(err)
				return
			}
			if info.ServerID == nil || info.ServerID.Raw != "SSH-2.0-OpenSSH_9.2p1 test" {
				t.Errorf("wrong server identity: %+v", info.ServerID)
			}
			if strings.Join(info.UserAuth, ",") != "password" {
				t.Errorf("methods must come from server: %v", info.UserAuth)
			}
			// Each caller must own its result even when the handshake is shared.
			info.UserAuth[0] = "changed"
		}()
	}
	wg.Wait()
	if n := connections.Load(); n != 1 {
		t.Errorf("handshakes=%d, want one", n)
	}
	if n := passwordAttempts.Load(); n != 0 {
		t.Errorf("password attempts=%d, want zero", n)
	}
}

func TestSSHHandshakeHonorsContextDeadline(t *testing.T) {
	for _, mode := range []string{"info", "password"} {
		t.Run(mode, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			defer close(done)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				<-done
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			client := NewSSHClient(ctx, 5*time.Second)
			port := ln.Addr().(*net.TCPAddr).Port
			start := time.Now()
			if mode == "info" {
				info, e := client.ConnectSSHInfoMode("127.0.0.1", port)
				if e == nil || info != nil {
					t.Fatalf("failed handshake returned invented info: %+v error=%v", info, e)
				}
			} else {
				ok, e := client.Connect("127.0.0.1", port, "test", "unused")
				if e == nil || ok {
					t.Fatalf("stalled handshake succeeded: %v %v", ok, e)
				}
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("context failed to stop handshake: %s", elapsed)
			}
		})
	}
}
