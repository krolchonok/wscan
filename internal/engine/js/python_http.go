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
	"runtime"
	"strconv"
	"strings"
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

// python3Command avoids Windows app aliases and accepts the py launcher.
func python3Command(ctx context.Context, args ...string) (*exec.Cmd, error) {
	candidates := []string{"python3", "python", "py"}
	if runtime.GOOS == "windows" {
		candidates = []string{"python", "py", "python3"}
	}
	for _, name := range candidates {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		var prefix []string
		if name == "py" {
			prefix = []string{"-3"}
		}
		check, cancel := context.WithTimeout(ctx, 4*time.Second)
		version, err := exec.CommandContext(check, path, append(prefix, "--version")...).CombinedOutput()
		cancel()
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(version)), "Python 3.") {
			continue
		}
		return exec.CommandContext(ctx, path, append(prefix, args...)...), nil
	}
	return nil, fmt.Errorf("HTTP: не найден рабочий Python 3 (python3, python или py -3)")
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
	cmd, e := python3Command(ctx, "-u", "-m", "http.server", strconv.Itoa(port), "--bind", "0.0.0.0", "--directory", dir)
	if e != nil {
		return nil, e
	}
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
