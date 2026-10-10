// Package ftpclient provides read-only FTP/FTPS browsing on a selected server.
package ftpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"
)

type Options struct {
	Host               string
	Port               int
	Mode               string // ftp, explicit (AUTH TLS), implicit
	Insecure           bool
	Username, Password string
	Timeout            time.Duration
}
type Entry struct {
	Name      string
	Directory bool
	Link      string
	Size      int64
	Modified  time.Time
}
type Directory struct {
	Path      string
	Entries   []Entry
	Truncated bool
}
type LoginError struct{ Err error }

func (e *LoginError) Error() string { return "FTP: ошибка входа: " + e.Err.Error() }
func (e *LoginError) Unwrap() error { return e.Err }

func AuthenticationRejected(err error) bool {
	var login *LoginError
	var response *textproto.Error
	return errors.As(err, &login) && errors.As(login.Err, &response) && (response.Code == 530 || response.Code == 532 || response.Code == 430)
}

func validValue(s string) bool { return !strings.ContainsAny(s, "\r\n\x00") }

type boundedConn struct {
	net.Conn
	remaining int64
}

func (c *boundedConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, fmt.Errorf("FTP: ответ превышает лимит")
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= int64(n)
	return n, err
}

type connections struct {
	sync.Mutex
	closed bool
	items  []net.Conn
}

func (c *connections) add(n net.Conn) error {
	c.Lock()
	defer c.Unlock()
	if c.closed {
		n.Close()
		return context.Canceled
	}
	c.items = append(c.items, n)
	return nil
}
func (c *connections) close() {
	c.Lock()
	defer c.Unlock()
	c.closed = true
	for _, n := range c.items {
		n.Close()
	}
}

func open(ctx context.Context, o Options, list bool) (*ftp.ServerConn, func(), error) {
	if o.Mode == "" {
		o.Mode = "ftp"
	}
	if o.Host == "" || o.Port < 1 || o.Port > 65535 || !validValue(o.Host+o.Username+o.Password) {
		return nil, nil, fmt.Errorf("FTP: некорректный адрес или учётка")
	}
	if o.Mode != "ftp" && o.Mode != "explicit" && o.Mode != "implicit" {
		return nil, nil, fmt.Errorf("FTP: неизвестный режим TLS")
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	conns := &connections{}
	stop := context.AfterFunc(ctx, conns.close)
	cleanup := func() { stop(); conns.close() }
	tlsConfig := &tls.Config{ServerName: o.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.Insecure, ClientSessionCache: tls.NewLRUClientSessionCache(8)}
	first := true
	dial := func(network, address string) (net.Conn, error) {
		n, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if err = conns.add(n); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok {
			deadline = d
		}
		if err = n.SetDeadline(deadline); err != nil {
			n.Close()
			return nil, err
		}
		control := first
		first = false
		if control && o.Mode == "implicit" {
			secure := tls.Client(n, tlsConfig)
			if err = secure.HandshakeContext(ctx); err != nil {
				n.Close()
				return nil, err
			}
			n = secure
		}
		if !control && o.Mode != "ftp" {
			n = tls.Client(n, tlsConfig)
		}
		if control {
			n = &boundedConn{Conn: n, remaining: 512 * 1024}
		} else if list {
			n = &boundedConn{Conn: n, remaining: 4 * 1024 * 1024}
		}
		return n, nil
	}
	opts := []ftp.DialOption{ftp.DialWithContext(ctx), ftp.DialWithDialFunc(dial), ftp.DialWithTrustPasvIP(false), ftp.DialWithShutTimeout(2 * time.Second)}
	if o.Mode == "explicit" {
		opts = append(opts, ftp.DialWithExplicitTLS(tlsConfig))
	} else if o.Mode == "implicit" {
		opts = append(opts, ftp.DialWithTLS(tlsConfig))
	}
	client, err := ftp.Dial(net.JoinHostPort(o.Host, strconv.Itoa(o.Port)), opts...)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if err = client.Login(o.Username, o.Password); err != nil {
		client.Quit()
		cleanup()
		return nil, nil, &LoginError{Err: err}
	}
	return client, func() { client.Quit(); cleanup() }, nil
}

func Browse(ctx context.Context, o Options, remote string) (Directory, error) {
	if !validValue(remote) {
		return Directory{}, fmt.Errorf("FTP: некорректный путь")
	}
	c, close, err := open(ctx, o, true)
	if err != nil {
		return Directory{}, err
	}
	defer close()
	if remote != "" {
		if err = c.ChangeDir(remote); err != nil {
			return Directory{}, err
		}
	}
	pwd, err := c.CurrentDir()
	if err != nil {
		return Directory{}, err
	}
	infos, err := c.List("")
	if err != nil {
		return Directory{}, err
	}
	result := Directory{Path: pwd}
	for _, e := range infos {
		if e.Name == "." || e.Name == ".." || !validValue(e.Name) || strings.ContainsAny(e.Name, "/\\") {
			continue
		}
		if len(result.Entries) == 1000 {
			result.Truncated = true
			break
		}
		size := int64(e.Size)
		if e.Size > math.MaxInt64 {
			size = -1
		}
		result.Entries = append(result.Entries, Entry{Name: e.Name, Directory: e.Type == ftp.EntryTypeFolder, Link: e.Target, Size: size, Modified: e.Time})
	}
	sort.Slice(result.Entries, func(i, j int) bool {
		a, b := result.Entries[i], result.Entries[j]
		if a.Directory != b.Directory {
			return a.Directory
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return result, nil
}

func Read(ctx context.Context, o Options, remote string, dst io.Writer, limit int64) (int64, error) {
	if !validValue(remote) {
		return 0, fmt.Errorf("FTP: некорректный путь")
	}
	c, close, err := open(ctx, o, false)
	if err != nil {
		return 0, err
	}
	defer close()
	response, err := c.Retr(remote)
	if err != nil {
		return 0, err
	}
	var reader io.Reader = response
	if limit > 0 {
		reader = io.LimitReader(response, limit)
	}
	n, err := io.Copy(dst, reader)
	closeErr := response.Close()
	// Closing a preview before EOF can cause an expected 426 on the discarded
	// session. For full downloads the completion reply must succeed.
	if err == nil && (limit <= 0 || n < limit) {
		err = closeErr
	}
	if ctx.Err() != nil {
		return n, ctx.Err()
	}
	return n, err
}

type progressWriter struct {
	dst      io.Writer
	written  int64
	progress func(int64)
}

func (w *progressWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	w.written += int64(n)
	if w.progress != nil {
		w.progress(w.written)
	}
	return n, err
}
func Download(ctx context.Context, o Options, remote, directory string, progress func(int64)) (string, error) {
	if !validValue(remote) {
		return "", fmt.Errorf("FTP: некорректный путь")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	name := path.Base(remote)
	if name == "." || name == "/" {
		return "", fmt.Errorf("FTP: выбери файл")
	}
	name = strings.ReplaceAll(strings.ReplaceAll(name, "\\", "_"), "*", "_")
	file, err := os.CreateTemp(directory, "ftp-*-"+name)
	if err != nil {
		return "", err
	}
	_, err = Read(ctx, o, remote, &progressWriter{dst: file, progress: progress}, 0)
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(file.Name())
		return "", err
	}
	return filepath.Clean(file.Name()), nil
}
