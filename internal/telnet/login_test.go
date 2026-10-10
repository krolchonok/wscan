package telnet

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLoginNegotiationAndResults(t *testing.T) {
	for _, tc := range []struct {
		name, pass, response string
		success, wantErr     bool
	}{
		{"root-root", "root", "\r\nWelcome\r\nroot@host:~# ", true, false},
		{"rejected", "wrong", "\r\nLogin incorrect\r\n", false, false},
		{"repeated-password", "wrong", "\r\nPassword:", false, false},
		{"ambiguous", "root", "\r\nWelcome\r\n", false, true},
		{"echo-is-not-shell", "#", "#\r\n", false, true},
		{"partial-echo-is-not-shell", "root#$", "root#$\r\ntext", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				server.SetDeadline(time.Now().Add(time.Second))
				_, err := server.Write([]byte{255, 251, 1})
				if err != nil {
					done <- err
					return
				}
				reply := make([]byte, 3)
				if _, err = io.ReadFull(server, reply); err != nil {
					done <- err
					return
				}
				if string(reply) != string([]byte{255, 254, 1}) {
					done <- io.ErrUnexpectedEOF
					return
				}
				for _, fragment := range []string{"\x1b[32mlo", "gin:\x1b[0m"} {
					if _, err = server.Write([]byte(fragment)); err != nil {
						done <- err
						return
					}
				}
				reader := bufio.NewReader(server)
				user, err := reader.ReadString('\n')
				if err != nil {
					done <- err
					return
				}
				if user != "root\r\n" {
					done <- io.ErrUnexpectedEOF
					return
				}
				if _, err = server.Write([]byte("Password:")); err != nil {
					done <- err
					return
				}
				pass, err := reader.ReadString('\n')
				if err != nil {
					done <- err
					return
				}
				if pass != tc.pass+"\r\n" {
					done <- io.ErrUnexpectedEOF
					return
				}
				// The client may finish on the prompt's final character.
				_, _ = server.Write([]byte(tc.response))
				done <- nil
			}()
			ok, err := Login(context.Background(), client, time.Second, "root", tc.pass)
			if ok != tc.success || (err != nil) != tc.wantErr {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoginCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err := Login(ctx, client, time.Minute, "root", "root")
	if ok || err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}
