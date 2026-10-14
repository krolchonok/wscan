package nse

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFTPAnonymousUsesBufferedMultilineReplies(t *testing.T) {
	lib := libraryDir(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = fmt.Fprint(c, "220-Welcome\r\n220 FTP ready\r\n")
		r := bufio.NewScanner(c)
		for r.Scan() {
			switch r.Text() {
			case "USER anonymous":
				_, _ = fmt.Fprint(c, "331 Password required\r\n")
			case "PASS IEUser@":
				_, _ = fmt.Fprint(c, "230-Logged in\r\n230 Anonymous allowed\r\n")
			case "QUIT":
				return
			default:
				_, _ = fmt.Fprint(c, "530 Login denied\r\n")
			}
		}
	}()
	r := New(lib, Config{Timeout: time.Second, ScriptTimeout: 3 * time.Second, Args: map[string]string{"ftp-anon.maxlist": "0"}})
	result, ran, err := r.Run(context.Background(), filepath.Join(lib, "nmap/scripts/ftp-anon.nse"), HostInfo{IP: "127.0.0.1"}, []PortInfo{{Number: ln.Addr().(*net.TCPAddr).Port, Protocol: "tcp", State: "open", Service: "ftp"}})
	if err != nil || !ran || len(result) != 1 || !strings.Contains(result[0].Output, "Anonymous FTP login allowed") {
		t.Fatalf("result=%v ran=%v err=%v", result, ran, err)
	}
}
