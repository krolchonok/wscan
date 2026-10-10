package engine

import (
	"context"
	"errors"
	realssh "golang.org/x/crypto/ssh"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"wscan/internal/domain"
)

func sshTestDictionary(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dictionary.txt")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestSSHDictionaryLockoutAndAttemptedPasswords(t *testing.T) {
	port := fakePasswordSSHServer(t, "admin", "correct")
	store := &fakeStore{}
	e := New(store, Config{TimeoutSeconds: 1})
	p := domain.Project{ID: 1, AllowCredentialAttack: true, LockoutMaxAttempts: 2}
	target := domain.Service{Host: "127.0.0.1", Port: port}
	var events int
	result, err := e.SSHDictionary(context.Background(), p, target, SSHDictionaryOptions{Username: "admin", Passwordlist: sshTestDictionary(t, "wrong1\nwrong2\ncorrect\n"), Delay: time.Nanosecond}, func(row SSHDictionaryAttempt) { events++ })
	if err != nil || result.Tried != 2 || result.Blocked != 1 || result.Found != 0 || events != 3 || store.failureCounts["admin"] != 2 {
		t.Fatalf("%+v err=%v events=%d", result, err, events)
	}
	if result.Attempts[0].Password != "wrong1" || result.Attempts[1].Password != "wrong2" || result.Attempts[2].Password != "" {
		t.Fatal("attempted passwords missing or skipped password shown")
	}
}
func TestSSHDictionarySuccessStopsAccountAndKeepsPassword(t *testing.T) {
	port := fakePasswordSSHServer(t, "admin", " correct ")
	store := &fakeStore{}
	e := New(store, Config{TimeoutSeconds: 1})
	result, err := e.SSHDictionary(context.Background(), domain.Project{ID: 1, AllowCredentialAttack: true}, domain.Service{Host: "127.0.0.1", Port: port}, SSHDictionaryOptions{Username: "admin", Passwordlist: sshTestDictionary(t, "wrong\n correct \nmore\n"), Delay: time.Nanosecond}, nil)
	if err != nil || result.Found != 1 || result.Tried != 2 || len(result.Attempts) != 2 || result.Attempts[1].Password != " correct " {
		t.Fatalf("%+v %v", result, err)
	}
}
func TestSSHDictionaryUsesExistingProjectFailureCount(t *testing.T) {
	store := &fakeStore{failureCounts: map[string]int{"admin": domain.DefaultLockoutMaxAttempts}}
	e := New(store, Config{})
	result, err := e.SSHDictionary(context.Background(), domain.Project{ID: 1, AllowCredentialAttack: true}, domain.Service{Host: "127.0.0.1", Port: 1}, SSHDictionaryOptions{Username: "admin", Passwordlist: sshTestDictionary(t, "one\ntwo\nthree\n")}, nil)
	if err != nil || result.Tried != 0 || result.Blocked != 1 || len(result.Attempts) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
}
func TestSSHDictionaryPermissionAndCancellation(t *testing.T) {
	e := New(&fakeStore{}, Config{})
	options := SSHDictionaryOptions{Username: "admin", Passwordlist: sshTestDictionary(t, "wrong\n")}
	target := domain.Service{Host: "127.0.0.1", Port: 22}
	if _, err := e.SSHDictionary(context.Background(), domain.Project{}, target, options, nil); err == nil {
		t.Fatal("permission gate bypassed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.SSHDictionary(ctx, domain.Project{AllowCredentialAttack: true}, target, options, nil); err != context.Canceled {
		t.Fatalf("%v", err)
	}
}
func TestSSHDictionaryUsernameFileAndDeduplication(t *testing.T) {
	users, err := sshDictionaryUsers(SSHDictionaryOptions{Userlist: sshTestDictionary(t, "admin\nroot\nadmin\n#comment\n\n")})
	if err != nil || len(users) != 2 || users[0] != "admin" || users[1] != "root" {
		t.Fatalf("%v %v", users, err)
	}
}

func TestSSHDictionaryCancellationPreservesAttemptLog(t *testing.T) {
	port := fakePasswordSSHServer(t, "admin", "correct")
	store := &fakeStore{}
	e := New(store, Config{TimeoutSeconds: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := e.SSHDictionary(ctx, domain.Project{ID: 1, AllowCredentialAttack: true}, domain.Service{Host: "127.0.0.1", Port: port}, SSHDictionaryOptions{Username: "admin", Passwordlist: sshTestDictionary(t, "wrong\ncorrect\n"), Delay: time.Nanosecond}, func(SSHDictionaryAttempt) { cancel() })
	if err != context.Canceled || result.Tried != 1 || store.failureCounts["admin"] != 1 {
		t.Fatalf("result=%+v err=%v failures=%v", result, err, store.failureCounts)
	}
}

func TestSSHDictionaryUnlimitedIgnoresThresholdAndRecordsAttempts(t *testing.T) {
	port := fakePasswordSSHServer(t, "admin", "correct")
	store := &fakeStore{failureCounts: map[string]int{"admin": 50}}
	e := New(store, Config{TimeoutSeconds: 1})
	result, err := e.SSHDictionary(context.Background(), domain.Project{ID: 1, AllowCredentialAttack: true, LockoutMaxAttempts: 1}, domain.Service{Host: "127.0.0.1", Port: port}, SSHDictionaryOptions{Username: "admin", Passwordlist: sshTestDictionary(t, "wrong1\nwrong2\ncorrect\n"), Delay: time.Nanosecond, Unlimited: true}, nil)
	if err != nil || result.Tried != 3 || result.Found != 1 || result.Blocked != 0 || store.failureCounts["admin"] != 52 {
		t.Fatalf("%+v %v failures=%v", result, err, store.failureCounts)
	}
}

func TestSSHDictionaryParallelWorkersAndRate(t *testing.T) {
	port := fakePasswordSSHServer(t, "admin", "correct")
	store := &fakeStore{}
	e := New(store, Config{TimeoutSeconds: 1})
	started := time.Now()
	result, err := e.SSHDictionary(context.Background(), domain.Project{ID: 1, AllowCredentialAttack: true}, domain.Service{Host: "127.0.0.1", Port: port}, SSHDictionaryOptions{Username: "admin", Passwordlist: sshTestDictionary(t, "wrong1\nwrong2\nwrong3\nwrong4\n"), Concurrency: 4, RPS: 20, Unlimited: true}, nil)
	if err != nil || result.Tried != 4 || store.failureCounts["admin"] != 4 || time.Since(started) < 190*time.Millisecond {
		t.Fatalf("%+v err=%v elapsed=%v", result, err, time.Since(started))
	}
}
func TestSSHDictionaryParallelLimitedDoesNotExceedThreshold(t *testing.T) {
	port := fakePasswordSSHServer(t, "admin", "unused")
	store := &fakeStore{}
	e := New(store, Config{TimeoutSeconds: 1})
	result, err := e.SSHDictionary(context.Background(), domain.Project{ID: 1, AllowCredentialAttack: true, LockoutMaxAttempts: 2}, domain.Service{Host: "127.0.0.1", Port: port}, SSHDictionaryOptions{Username: "admin", Passwordlist: sshTestDictionary(t, "wrong1\nwrong2\nwrong3\nwrong4\nwrong5\n"), Concurrency: 4}, nil)
	if err != nil || result.Tried != 2 || result.Blocked != 1 || store.failureCounts["admin"] != 2 {
		t.Fatalf("%+v err=%v failures=%v", result, err, store.failureCounts)
	}
}

func TestSSHDictionaryActuallyOpensParallelConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 4)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func() { defer conn.Close(); <-stop }()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	e := New(&fakeStore{}, Config{TimeoutSeconds: 3})
	options := SSHDictionaryOptions{Username: "admin", Passwordlist: sshTestDictionary(t, "one\ntwo\nthree\nfour\n"), Concurrency: 4, Unlimited: true}
	go func() {
		_, err := e.SSHDictionary(ctx, domain.Project{AllowCredentialAttack: true}, domain.Service{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}, options, nil)
		done <- err
	}()
	for i := 0; i < 4; i++ {
		select {
		case <-accepted:
		case <-time.After(time.Second):
			cancel()
			<-done
			t.Fatal("workers did not open four concurrent connections")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("parallel cancellation stalled")
	}
}

func TestSSHDictionarySuccessCancelsInFlightAccountAttempts(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	ready := make(chan struct{}, 2)
	var afterSuccess atomic.Int32
	port := callbackPasswordSSHServer(t, func(conn realssh.ConnMetadata, password []byte) (*realssh.Permissions, error) {
		if string(password) == "correct" {
			for i := 0; i < 2; i++ {
				select {
				case <-ready:
				case <-time.After(time.Second):
					return nil, errors.New("missing parallel attempts")
				}
			}
			return &realssh.Permissions{}, nil
		}
		if string(password) == "late" {
			afterSuccess.Add(1)
		}
		ready <- struct{}{}
		<-blocked
		return nil, errors.New("wrong credentials")
	})
	store := &fakeStore{}
	e := New(store, Config{TimeoutSeconds: 5})
	started := time.Now()
	result, err := e.SSHDictionary(context.Background(), domain.Project{ID: 1, AllowCredentialAttack: true}, domain.Service{Host: "127.0.0.1", Port: port}, SSHDictionaryOptions{Username: "admin", Passwordlist: sshTestDictionary(t, "slow1\nslow2\ncorrect\nlate\nlate\n"), Concurrency: 3, Unlimited: true}, nil)
	cancelled := 0
	for _, a := range result.Attempts {
		if a.Cancelled {
			cancelled++
		}
	}
	if err != nil || result.Found != 1 || cancelled != 2 || afterSuccess.Load() != 0 || time.Since(started) > 2*time.Second {
		t.Fatalf("result=%+v cancelled=%d err=%v elapsed=%v", result, cancelled, err, time.Since(started))
	}
}
func TestSSHDictionarySuccessDoesNotStopOtherAccounts(t *testing.T) {
	port := callbackPasswordSSHServer(t, func(conn realssh.ConnMetadata, password []byte) (*realssh.Permissions, error) {
		if (conn.User() == "admin" && string(password) == "first") || (conn.User() == "other" && string(password) == "second") {
			return &realssh.Permissions{}, nil
		}
		return nil, errors.New("wrong credentials")
	})
	e := New(&fakeStore{}, Config{TimeoutSeconds: 1})
	result, err := e.SSHDictionary(context.Background(), domain.Project{AllowCredentialAttack: true}, domain.Service{Host: "127.0.0.1", Port: port}, SSHDictionaryOptions{Userlist: sshTestDictionary(t, "admin\nother\n"), Passwordlist: sshTestDictionary(t, "first\nsecond\n"), Concurrency: 2, Unlimited: true}, nil)
	if err != nil || result.Found != 2 {
		t.Fatalf("%+v %v", result, err)
	}
}
