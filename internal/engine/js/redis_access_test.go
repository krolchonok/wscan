package js

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dop251/goja"
)

func fakeRedisAccess(t *testing.T, noauth bool, password string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second))
				r := bufio.NewReader(c)
				authenticated := noauth
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if !strings.HasPrefix(line, "*") {
						return
					}
					argc, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
					if argc < 1 || argc > 4 {
						return
					}
					args := make([]string, argc)
					for i := range args {
						line, err = r.ReadString('\n')
						if err != nil {
							return
						}
						n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
						if n < 0 || n > 1024 {
							return
						}
						p := make([]byte, n+2)
						if _, err = io.ReadFull(r, p); err != nil {
							return
						}
						args[i] = string(p[:n])
					}
					switch args[0] {
					case "AUTH":
						if len(args) == 2 && args[1] == password {
							authenticated = true
							io.WriteString(c, "+OK\r\n")
						} else {
							io.WriteString(c, "-WRONGPASS invalid username-password pair\r\n")
						}
					case "INFO":
						if !authenticated {
							io.WriteString(c, "-NOAUTH Authentication required.\r\n")
						} else {
							body := "redis_version:7.4.0\r\n"
							fmt.Fprintf(c, "$%d\r\n%s\r\n", len(body), body)
						}
					default:
						io.WriteString(c, "-ERR unexpected command\r\n")
					}
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}
func TestRedisNoAuthAndTrueEmptyAuthAreSeparate(t *testing.T) {
	port := fakeRedisAccess(t, false, "")
	vm := goja.New()
	vm.Set("m", redisModule(vm, context.Background(), time.Second))
	vm.Set("port", port)
	if _, err := vm.RunString(`m.GetServerInfo("127.0.0.1",port)`); err == nil {
		t.Fatal("INFO without AUTH unexpectedly worked")
	}
	v, err := vm.RunString(`m.GetServerInfoWithEmptyPassword("127.0.0.1",port)`)
	if err != nil || !strings.Contains(v.String(), "redis_version:") {
		t.Fatalf("empty AUTH=%v err=%v", v, err)
	}
	other := fakeRedisAccess(t, false, "secret")
	ok, err := CheckRedisPassword(context.Background(), "127.0.0.1", other, "wrong", time.Second)
	if err == nil || ok {
		t.Fatal("wrong Redis password accepted")
	}
	ok, err = CheckRedisPassword(context.Background(), "127.0.0.1", other, "secret", time.Second)
	if err != nil || !ok {
		t.Fatalf("correct Redis password: %v", err)
	}
}
