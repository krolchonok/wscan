package nse

import (
	"errors"
	"fmt"
	"net"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// opencon/tryssl return a live socket, unlike exchange/get_banner. Mail
// libraries use the early response as the greeting before sending commands.
func (c *control) commOpencon(L *lua.LState) int {
	return c.commConnect(L, false)
}

func (c *control) commTrySSL(L *lua.LState) int {
	return c.commConnect(L, true)
}

func (c *control) commConnect(L *lua.LState, trySSL bool) int {
	host, msg := resolveConnectHost(L, L.Get(1))
	if msg != "" {
		L.ArgError(1, msg)
		return 0
	}
	port, proto, msg := resolveConnectPort(L, L.Get(2))
	if msg != "" {
		L.ArgError(2, msg)
		return 0
	}
	if proto == "" {
		proto = "tcp"
	}
	opts, _ := L.Get(4).(*lua.LTable)
	option := func(key string) lua.LValue {
		if opts == nil {
			return lua.LNil
		}
		return opts.RawGetString(key)
	}
	if v := option("proto"); v != lua.LNil {
		proto = v.String()
	}
	protocols := []string{proto}
	if trySSL && proto != "udp" {
		protocols = []string{"tcp", "ssl"}
		number, service := portFields(L, 2)
		secure := number == 465 || number == 993 || number == 995 || number == 443 || number == 8443 || service == "smtps" || service == "imaps" || service == "pop3s" || service == "https"
		if p, ok := L.Get(2).(*lua.LTable); ok {
			if v, ok := p.RawGetString("version").(*lua.LTable); ok && v.RawGetString("service_tunnel").String() == "ssl" {
				secure = true
			}
		}
		if secure {
			protocols = []string{"ssl", "tcp"}
		}
	}
	var lastErr error
	var attemptErrors []error
	for _, protocol := range protocols {
		sock, response, early, err := c.openComm(host, port, protocol, L.OptString(3, ""), option)
		if err != nil {
			lastErr = err
			attemptErrors = append(attemptErrors, fmt.Errorf("%s %s:%d: %w", protocol, host, port, err))
			continue
		}
		ud := L.NewUserData()
		ud.Value = sock
		L.SetMetatable(ud, L.GetTypeMetatable(socketType))
		L.Push(ud)
		L.Push(response)
		if trySSL {
			L.Push(lua.LString(protocol))
		}
		L.Push(early)
		if trySSL {
			return 4
		}
		return 3
	}
	c.commErrors = append(c.commErrors, errors.Join(attemptErrors...))
	L.Push(lua.LNil)
	L.Push(lua.LString(lastErr.Error()))
	if trySSL {
		L.Push(lua.LString("none"))
	}
	L.Push(lua.LString(lastErr.Error()))
	if trySSL {
		return 4
	}
	return 3
}

func (c *control) openComm(host string, port int, proto, data string, option func(string) lua.LValue) (*luaSocket, lua.LValue, lua.LValue, error) {
	network := proto
	if network == "ssl" {
		network = "tcp"
	}
	if network != "tcp" && network != "udp" {
		return nil, nil, nil, fmt.Errorf("invalid connection method %q", proto)
	}
	conn, err := c.dial(network, net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return nil, nil, nil, err
	}
	sock := &luaSocket{ctrl: c, conn: conn, timeout: c.timeout}
	if ms := lua.LVAsNumber(option("timeout")); ms > 0 {
		sock.timeout = time.Duration(ms) * time.Millisecond
	}
	c.sockets = append(c.sockets, sock)
	fail := func(err error) (*luaSocket, lua.LValue, lua.LValue, error) {
		_ = conn.Close()
		sock.conn = nil
		return nil, nil, nil, err
	}
	if proto == "ssl" {
		if err := sock.startTLS(host); err != nil {
			return fail(err)
		}
	}
	read := func() (lua.LValue, error) {
		minBytes := max(1, int(lua.LVAsNumber(option("bytes"))))
		minLines := max(0, int(lua.LVAsNumber(option("lines"))))
		if minLines > 0 {
			minBytes = 1
		}
		data, err := sock.readResponse(minBytes, minLines)
		if err != nil {
			return lua.LNil, err
		}
		return lua.LString(string(data)), nil
	}
	var early, response lua.LValue = lua.LNil, lua.LNil
	if lua.LVAsBool(option("recv_before")) {
		early, err = read()
		if err != nil {
			return fail(err)
		}
		response = early
	}
	if data != "" {
		sock.applyDeadline()
		if _, err := sock.conn.Write([]byte(data)); err != nil {
			return fail(err)
		}
		response, err = read()
		if err != nil {
			return fail(err)
		}
	}
	return sock, response, early, nil
}
