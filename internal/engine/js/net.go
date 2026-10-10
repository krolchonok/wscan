package js

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"time"

	"github.com/dop251/goja"
)

func netModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	obj := vm.NewObject()
	_ = obj.Set("Open", func(call goja.FunctionCall) goja.Value {
		protocol := call.Argument(0).String()
		address := call.Argument(1).String()
		conn, err := dialNet(ctx, protocol, address, timeout, false)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(conn)
	})
	_ = obj.Set("OpenTLS", func(call goja.FunctionCall) goja.Value {
		protocol := call.Argument(0).String()
		address := call.Argument(1).String()
		conn, err := dialNet(ctx, protocol, address, timeout, true)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(conn)
	})
	return obj
}

func dialNet(ctx context.Context, protocol, address string, timeout time.Duration, useTLS bool) (*NetConn, error) {
	if protocol == "" {
		protocol = "tcp"
	}
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, protocol, address)
	if err != nil {
		return nil, err
	}
	if useTLS {
		host, _, _ := net.SplitHostPort(address)
		tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS10})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		raw = tlsConn
	}
	return &NetConn{conn: raw, timeout: timeout}, nil
}

// NetConn is the nuclei/net connection object returned by Open / OpenTLS.
type NetConn struct {
	conn    net.Conn
	timeout time.Duration
}

func (c *NetConn) Close() error {
	return c.conn.Close()
}

func (c *NetConn) SetTimeout(value int) {
	if value > 0 {
		c.timeout = time.Duration(value) * time.Second
	}
}

func (c *NetConn) setDeadline() {
	if c.timeout <= 0 {
		c.timeout = defaultDialTimeout
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))
}

func (c *NetConn) clearDeadline() {
	_ = c.conn.SetDeadline(time.Time{})
}

func (c *NetConn) Send(data string) error {
	c.setDeadline()
	defer c.clearDeadline()
	_, err := c.conn.Write([]byte(data))
	return err
}

func (c *NetConn) SendHex(data string) error {
	c.setDeadline()
	defer c.clearDeadline()
	bin, err := hex.DecodeString(data)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(bin)
	return err
}

func (c *NetConn) Recv(n int) ([]byte, error) {
	c.setDeadline()
	defer c.clearDeadline()
	if n <= 0 {
		n = 4096
	}
	buf := make([]byte, n)
	got, err := c.conn.Read(buf)
	if got > 0 {
		return buf[:got], nil
	}
	if err != nil {
		return []byte{}, err
	}
	return []byte{}, nil
}

func (c *NetConn) RecvString(n int) (string, error) {
	b, err := c.Recv(n)
	return string(b), err
}

func (c *NetConn) RecvHex(n int) (string, error) {
	b, err := c.Recv(n)
	return hex.Dump(b), err
}

func (c *NetConn) RecvFull(n int) ([]byte, error) {
	c.setDeadline()
	defer c.clearDeadline()
	if n <= 0 {
		n = 8 << 20 // 8 MiB cap, matching nuclei
	}
	buf := make([]byte, 0, min(n, 64*1024))
	tmp := make([]byte, min(n, 32*1024))
	for len(buf) < n {
		want := n - len(buf)
		if want > len(tmp) {
			want = len(tmp)
		}
		got, err := c.conn.Read(tmp[:want])
		if got > 0 {
			buf = append(buf, tmp[:got]...)
		}
		if err != nil {
			if err == io.EOF && len(buf) > 0 {
				return buf, nil
			}
			if len(buf) > 0 {
				return buf, nil
			}
			return []byte{}, err
		}
		if got == 0 {
			break
		}
	}
	return buf, nil
}

func (c *NetConn) RecvFullString(n int) (string, error) {
	b, err := c.RecvFull(n)
	return string(b), err
}

func (c *NetConn) RecvFullHex(n int) (string, error) {
	b, err := c.RecvFull(n)
	return hex.Dump(b), err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
