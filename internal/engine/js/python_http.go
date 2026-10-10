package js

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

type PythonFileServer struct {
	URL, SHA256 string
	cmd         *exec.Cmd
	done        chan error
	dir         string
	once        sync.Once
}

// HTTPAddressForTarget selects the interface used to reach the chosen host.
func HTTPAddressForTarget(host string) string {
	c, e := net.Dial("udp", net.JoinHostPort(host, "1433"))
	if e != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

// StartPythonFileServer serves an immutable snapshot of just the selected file.
// Close is required after the transfer; cancellation also stops the server.
func StartPythonFileServer(ctx context.Context, file, address string, port int) (*PythonFileServer, error) {
	if net.ParseIP(address) == nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("HTTP: укажи IP, доступный Windows, и порт 1–65535")
	}
	src, e := os.Open(file)
	if e != nil {
		return nil, e
	}
	defer src.Close()
	st, e := src.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > 128*1024*1024 {
		return nil, fmt.Errorf("HTTP: нужен обычный файл до 128 МиБ")
	}
	dir, e := os.MkdirTemp("", "wscan-http-")
	if e != nil {
		return nil, e
	}
	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(dir)
		}
	}()
	dst, e := os.Create(filepath.Join(dir, "payload"))
	if e != nil {
		return nil, e
	}
	hash := sha256.New()
	n, e := io.Copy(io.MultiWriter(dst, hash), io.LimitReader(src, 128*1024*1024+1))
	ce := dst.Close()
	if e != nil {
		return nil, e
	}
	if ce != nil {
		return nil, ce
	}
	if n > 128*1024*1024 {
		return nil, fmt.Errorf("HTTP: файл превышает 128 МиБ")
	}
	cmd := exec.CommandContext(ctx, "python3", "-u", "-m", "http.server", strconv.Itoa(port), "--bind", "0.0.0.0", "--directory", dir)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return nil, e
	}
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		return nil, e
	}
	s := &PythonFileServer{cmd: cmd, done: make(chan error, 1), dir: dir, SHA256: hex.EncodeToString(hash.Sum(nil))}
	ready := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(pipe)
		re := regexp.MustCompile(`Serving HTTP .* port ([0-9]+)`)
		for scan.Scan() {
			if m := re.FindStringSubmatch(scan.Text()); len(m) > 1 {
				select {
				case ready <- m[1]:
				default:
				}
			}
		}
	}()
	go func() { s.done <- cmd.Wait(); close(s.done) }()
	select {
	case p := <-ready:
		s.URL = (&url.URL{Scheme: "http", Host: net.JoinHostPort(address, p), Path: "/payload"}).String()
		cleanup = false
		go func() {
			select {
			case <-ctx.Done():
				s.Close()
			case <-s.done:
			}
		}()
		return s, nil
	case <-s.done:
		s.Close()
		return nil, fmt.Errorf("Python HTTP-сервер не запустился: проверь свободный порт")
	case <-ctx.Done():
		s.Close()
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		s.Close()
		return nil, fmt.Errorf("Python HTTP-сервер не сообщил о готовности")
	}
}
func (s *PythonFileServer) Close() {
	s.once.Do(func() {
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		<-s.done
		_ = os.RemoveAll(s.dir)
	})
}
