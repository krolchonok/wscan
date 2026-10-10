package nse

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// control is the single choke point every Lua network call goes through, so the
// engine — not the script — owns rate limiting, timeouts and cancellation. A
// script cannot open a raw connection that bypasses these.
type control struct {
	ctx          context.Context
	dialer       net.Dialer
	client       *http.Client
	timeout      time.Duration
	limiter      <-chan time.Time
	stop         func()
	sockets      []*luaSocket
	commErrors   []error
	allowedHosts map[string]bool
	allowedPorts map[string]bool
}

func (c *control) close() {
	c.client.CloseIdleConnections()
	for _, s := range c.sockets {
		if s.conn != nil {
			_ = s.conn.Close()
			s.conn = nil
		}
	}
	if c.stop != nil {
		c.stop()
	}
}

func newControl(ctx context.Context, cfg Config) *control {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	c := &control{
		ctx:     ctx,
		dialer:  net.Dialer{Timeout: timeout},
		timeout: timeout,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
	if cfg.RPS > 0 {
		interval := time.Second / time.Duration(cfg.RPS)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		t := time.NewTicker(interval)
		c.limiter = t.C
		c.stop = t.Stop
	}
	return c
}

func (c *control) wait() error {
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	if c.limiter == nil {
		return nil
	}
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-c.limiter:
		return nil
	}
}

func (c *control) dial(network, address string) (net.Conn, error) {
	if err := c.checkScope(network, address); err != nil {
		return nil, err
	}
	if err := c.wait(); err != nil {
		return nil, err
	}
	return c.dialer.DialContext(c.ctx, network, address)
}

func (c *control) do(req *http.Request) (*http.Response, error) {
	if err := c.checkScope("tcp", requestEndpoint(req)); err != nil {
		return nil, err
	}
	if err := c.wait(); err != nil {
		return nil, err
	}
	return c.client.Do(req.WithContext(c.ctx))
}

// --- Lua socket object (nmap.new_socket) --------------------------------

type luaSocket struct {
	ctrl    *control
	conn    net.Conn
	timeout time.Duration
	buf     []byte // leftover from receive_buf
}

const socketType = "nmap.socket"

func registerSocketType(L *lua.LState) {
	mt := L.NewTypeMetatable(socketType)
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"connect":       socketConnect,
		"reconnect_ssl": socketReconnectSSL,
		"send":          socketSend,
		"receive":       socketReceive,
		"receive_lines": socketReceiveLines,
		"receive_bytes": socketReceiveBytes,
		"receive_buf":   socketReceiveBuf,
		"get_info":      socketGetInfo,
		"set_timeout":   socketSetTimeout,
		"close":         socketClose,
	}))
}

func checkSocket(L *lua.LState) *luaSocket {
	ud := L.CheckUserData(1)
	if s, ok := ud.Value.(*luaSocket); ok {
		return s
	}
	L.ArgError(1, "nmap socket expected")
	return nil
}

func socketConnect(L *lua.LState) int {
	s := checkSocket(L)
	host, errMsg := resolveConnectHost(L, L.Get(2))
	if errMsg != "" {
		L.Push(lua.LFalse)
		L.Push(lua.LString(errMsg))
		return 2
	}
	port, protoFromPort, errMsg := resolveConnectPort(L, L.Get(3))
	if errMsg != "" {
		L.Push(lua.LFalse)
		L.Push(lua.LString(errMsg))
		return 2
	}
	proto := strings.ToLower(L.OptString(4, ""))
	if proto == "" {
		proto = protoFromPort
	}
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" && proto != "ssl" {
		L.Push(lua.LFalse)
		L.Push(lua.LString("invalid connection method"))
		return 2
	}
	network := proto
	if network == "ssl" {
		network = "tcp"
	}
	conn, err := s.ctrl.dial(network, net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	s.conn = conn
	if proto == "ssl" {
		if err := s.startTLS(host); err != nil {
			L.Push(lua.LFalse)
			L.Push(lua.LString(err.Error()))
			return 2
		}
	}
	L.Push(lua.LTrue)
	return 1
}

// NSE probes inspect servers with arbitrary certificates, including self-signed ones.
func (s *luaSocket) startTLS(host string) error {
	s.applyDeadline()
	conn := tls.Client(s.conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := conn.HandshakeContext(s.ctrl.ctx); err != nil {
		_ = conn.Close()
		s.conn = nil
		return err
	}
	s.conn = conn
	return nil
}

func socketReconnectSSL(L *lua.LState) int {
	s := checkSocket(L)
	if s.conn == nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString("socket not connected"))
		return 2
	}
	host, _, _ := net.SplitHostPort(s.conn.RemoteAddr().String())
	if err := s.startTLS(host); err != nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LTrue)
	return 1
}

func resolveConnectHost(L *lua.LState, v lua.LValue) (string, string) {
	switch x := v.(type) {
	case lua.LString:
		s := string(x)
		if s == "" {
			return "", "empty host"
		}
		return s, ""
	case *lua.LTable:
		if ip := L.GetField(x, "ip"); ip.Type() == lua.LTString && ip.String() != "" {
			return ip.String(), ""
		}
		if name := L.GetField(x, "name"); name.Type() == lua.LTString && name.String() != "" {
			return name.String(), ""
		}
		return "", "host table missing ip/name"
	default:
		return "", "string expected, got " + v.Type().String()
	}
}

func resolveConnectPort(L *lua.LState, v lua.LValue) (int, string, string) {
	switch x := v.(type) {
	case lua.LNumber:
		return int(x), "", ""
	case lua.LString:
		n, err := strconv.Atoi(string(x))
		if err != nil {
			return 0, "", "bad port"
		}
		return n, "", ""
	case *lua.LTable:
		num := int(lua.LVAsNumber(L.GetField(x, "number")))
		if num == 0 {
			return 0, "", "port table missing number"
		}
		proto := L.GetField(x, "protocol").String()
		return num, proto, ""
	default:
		return 0, "", "port expected, got " + v.Type().String()
	}
}

func socketSend(L *lua.LState) int {
	s := checkSocket(L)
	data := L.CheckString(2)
	if s.conn == nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString("socket not connected"))
		return 2
	}
	s.applyDeadline()
	if _, err := s.conn.Write([]byte(data)); err != nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LTrue)
	return 1
}

func socketReceive(L *lua.LState) int {
	s := checkSocket(L)
	if s.conn == nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString("socket not connected"))
		return 2
	}
	s.applyDeadline()
	buf := make([]byte, 4096)
	n, err := s.conn.Read(buf)
	if n > 0 {
		L.Push(lua.LTrue)
		L.Push(lua.LString(string(buf[:n])))
		return 2
	}
	msg := "EOF"
	if err != nil {
		msg = err.Error()
	}
	L.Push(lua.LFalse)
	L.Push(lua.LString(msg))
	return 2
}

func (s *luaSocket) readResponse(minBytes, minLines int) ([]byte, error) {
	out := s.buf
	s.buf = nil
	for len(out) < minBytes || bytes.Count(out, []byte{'\n'}) < minLines {
		s.applyDeadline()
		buf := make([]byte, 65535)
		n, err := s.conn.Read(buf)
		out = append(out, buf[:n]...)
		if len(out) >= minBytes && bytes.Count(out, []byte{'\n'}) >= minLines {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if isUDPAddr(s.conn) {
			return out, nil
		}
	}
	return out, nil
}

func socketReceiveLines(L *lua.LState) int {
	s := checkSocket(L)
	if s.conn == nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString("socket not connected"))
		return 2
	}
	data, err := s.readResponse(1, max(1, L.OptInt(2, 1)))
	if err != nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LTrue)
	L.Push(lua.LString(string(data)))
	return 2
}

func socketReceiveBytes(L *lua.LState) int {
	s := checkSocket(L)
	need := L.CheckInt(2)
	if s.conn == nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString("socket not connected"))
		return 2
	}
	s.applyDeadline()
	if need <= 0 {
		need = 1
	}
	// NSE receive_bytes(n) means "at least n bytes", not a fixed-size read.
	// Use a large buffer so a single UDP datagram is not truncated.
	chunk := 65535
	if need > chunk {
		chunk = need
	}
	var out []byte
	for len(out) < need {
		s.applyDeadline()
		buf := make([]byte, chunk)
		n, err := s.conn.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if len(out) >= need {
				break
			}
			msg := "EOF"
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				msg = err.Error()
			}
			L.Push(lua.LFalse)
			L.Push(lua.LString(msg))
			return 2
		}
		// UDP: one datagram is the complete message; don't block for more.
		if _, ok := s.conn.(*net.UDPConn); ok || isUDPAddr(s.conn) {
			break
		}
	}
	if len(out) == 0 {
		L.Push(lua.LFalse)
		L.Push(lua.LString("EOF"))
		return 2
	}
	L.Push(lua.LTrue)
	L.Push(lua.LString(string(out)))
	return 2
}

func isUDPAddr(c net.Conn) bool {
	if c == nil || c.RemoteAddr() == nil {
		return false
	}
	return strings.HasPrefix(c.RemoteAddr().Network(), "udp")
}

// socketReceiveBuf mirrors nmap's receive_buf(delimiter, keeppattern).
// delimiter is a string.find-style function (e.g. match.numbytes) or a Lua pattern string.
func socketReceiveBuf(L *lua.LState) int {
	s := checkSocket(L)
	delim := L.Get(2)
	keep := L.OptBool(3, true)
	if s.conn == nil {
		L.Push(lua.LFalse)
		L.Push(lua.LString("socket not connected"))
		return 2
	}

	findDelim := func(buf string) (start, end int, ok bool) {
		switch d := delim.(type) {
		case *lua.LFunction:
			top := L.GetTop()
			if err := L.CallByParam(lua.P{Fn: d, NRet: 2, Protect: true}, lua.LString(buf)); err != nil {
				return 0, 0, false
			}
			a, b := L.Get(-2), L.Get(-1)
			L.SetTop(top)
			if a == lua.LNil {
				return 0, 0, false
			}
			return int(lua.LVAsNumber(a)), int(lua.LVAsNumber(b)), true
		case lua.LString:
			// Lua pattern via string.find
			top := L.GetTop()
			strFind := L.GetField(L.GetGlobal("string"), "find")
			if err := L.CallByParam(lua.P{Fn: strFind, NRet: 2, Protect: true}, lua.LString(buf), d); err != nil {
				L.SetTop(top)
				return 0, 0, false
			}
			a, b := L.Get(-2), L.Get(-1)
			L.SetTop(top)
			if a == lua.LNil {
				return 0, 0, false
			}
			return int(lua.LVAsNumber(a)), int(lua.LVAsNumber(b)), true
		default:
			return 0, 0, false
		}
	}

	for {
		if start, end, ok := findDelim(string(s.buf)); ok {
			var out []byte
			if keep {
				out = append([]byte(nil), s.buf[:end]...)
			} else {
				out = append([]byte(nil), s.buf[:start-1]...)
			}
			s.buf = append([]byte(nil), s.buf[end:]...)
			L.Push(lua.LTrue)
			L.Push(lua.LString(string(out)))
			return 2
		}
		s.applyDeadline()
		chunk := make([]byte, 4096)
		n, err := s.conn.Read(chunk)
		if n > 0 {
			s.buf = append(s.buf, chunk[:n]...)
			continue
		}
		msg := "EOF"
		if err != nil && err != io.EOF {
			msg = err.Error()
		}
		L.Push(lua.LFalse)
		L.Push(lua.LString(msg))
		return 2
	}
}

func socketGetInfo(L *lua.LState) int {
	s := checkSocket(L)
	if s.conn == nil {
		L.Push(lua.LFalse)
		return 1
	}
	local := s.conn.LocalAddr().String()
	remote := s.conn.RemoteAddr().String()
	lh, lp, _ := net.SplitHostPort(local)
	rh, rp, _ := net.SplitHostPort(remote)
	L.Push(lua.LTrue)
	L.Push(lua.LString(lh))
	L.Push(lua.LString(lp))
	L.Push(lua.LString(rh))
	L.Push(lua.LString(rp))
	return 5
}

func socketSetTimeout(L *lua.LState) int {
	s := checkSocket(L)
	ms := L.CheckInt(2)
	s.timeout = time.Duration(ms) * time.Millisecond
	return 0
}

func socketClose(L *lua.LState) int {
	s := checkSocket(L)
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	L.Push(lua.LTrue)
	return 1
}

func (s *luaSocket) applyDeadline() {
	if s.conn == nil {
		return
	}
	timeout := s.timeout
	if timeout <= 0 {
		timeout = s.ctrl.timeout
	}
	deadline := time.Now().Add(timeout)
	if d, ok := s.ctrl.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = s.conn.SetDeadline(deadline)
}
