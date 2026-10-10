package nse

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func timeoutScript(t *testing.T, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "timeout-test.nse")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestScriptTimeLimit(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want time.Duration
	}{{Config{}, 30 * time.Second}, {Config{Timeout: 20 * time.Second}, 60 * time.Second}, {Config{Timeout: 20 * time.Second, ScriptTimeout: time.Second}, time.Second}} {
		if got := New("", tc.cfg).ScriptTimeLimit(); got != tc.want {
			t.Fatalf("got %s want %s", got, tc.want)
		}
	}
}
func TestScriptTimeoutStopsLuaAndNextScriptRuns(t *testing.T) {
	r := New(libraryDir(t), Config{ScriptTimeout: 50 * time.Millisecond})
	path := timeoutScript(t, `hostrule=function() return true end; action=function() while true do end end`)
	ctx := context.Background()
	started := time.Now()
	_, ran, err := r.Run(ctx, path, HostInfo{IP: "127.0.0.1"}, nil)
	if !ran || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "timeout-test.nse") {
		t.Fatalf("ran=%t err=%v", ran, err)
	}
	if time.Since(started) > time.Second || ctx.Err() != nil {
		t.Fatal("timeout leaked into parent or did not stop")
	}
	path = timeoutScript(t, `hostrule=function() return true end; action=function() return "next script" end`)
	res, ran, err := r.Run(ctx, path, HostInfo{}, nil)
	if err != nil || !ran || len(res) != 1 || res[0].Output != "next script" {
		t.Fatalf("next script: %v %v", res, err)
	}
}
func TestScriptTimeoutInterruptsSocketRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		<-stop
	}()
	path := timeoutScript(t, fmt.Sprintf(`local nmap=require "nmap"
hostrule=function() return true end
action=function(host) local s=nmap.new_socket(); s:set_timeout(60000); local ok=s:connect(host.ip,%d); if not ok then return "connect failed" end; s:receive_bytes(1); return "done" end`, ln.Addr().(*net.TCPAddr).Port))
	r := New(libraryDir(t), Config{Timeout: time.Minute, ScriptTimeout: 100 * time.Millisecond})
	started := time.Now()
	_, _, err = r.Run(context.Background(), path, HostInfo{IP: "127.0.0.1"}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("socket ignored script deadline")
	}
}
func TestScriptTimeoutPreservesParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := New(libraryDir(t), Config{}).Run(ctx, timeoutScript(t, `hostrule=function() return true end; action=function() return "x" end`), HostInfo{}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}
