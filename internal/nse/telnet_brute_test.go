package nse

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeTelnetBruteRootRoot(t *testing.T) {
	for _, accept := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "guess-limit"}[accept], func(t *testing.T) {
			dir := t.TempDir()
			script := filepath.Join(dir, "telnet-brute.nse")
			users := filepath.Join(dir, "users")
			passes := filepath.Join(dir, "passes")
			for p, s := range map[string]string{script: "-- native Telnet script fixture", users: "root\n", passes: "wrong\nsecond\nthird\n"} {
				if err := os.WriteFile(p, []byte(s), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			var attempts atomic.Int32
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
						attempts.Add(1)
						if accept && u == "root\r\n" && p == "root\r\n" {
							c.Write([]byte("\r\nroot@host:~#"))
						} else {
							c.Write([]byte("\r\nLogin incorrect"))
						}
					}()
				}
			}()
			port := ln.Addr().(*net.TCPAddr).Port
			runner := New(dir, Config{Timeout: time.Second, SelectedServicesOnly: true, Args: map[string]string{"userdb": users, "passdb": passes, "brute.guesses": "2"}})
			results, ran, err := runner.Run(context.Background(), script, HostInfo{IP: "127.0.0.1"}, []PortInfo{{Number: port, Protocol: "tcp", State: "open", Service: "telnet"}})
			if err != nil || !ran {
				t.Fatalf("ran=%v err=%v", ran, err)
			}
			if accept {
				if len(results) != 1 || !strings.Contains(results[0].Output, "root: valid credential") || attempts.Load() != 1 {
					t.Fatalf("results=%v attempts=%d", results, attempts.Load())
				}
			} else {
				if len(results) != 0 || attempts.Load() != 2 {
					t.Fatalf("results=%v attempts=%d", results, attempts.Load())
				}
			}
		})
	}
}
