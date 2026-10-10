package js

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
)

func redisModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	obj := vm.NewObject()
	_ = obj.Set("GetServerInfoWithEmptyPassword", func(call goja.FunctionCall) goja.Value {
		host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		conn, err := redisDial(ctx, host, port, timeout)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		defer conn.Close()
		reply, err := redisCmd(conn, "AUTH", "")
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		if reply != "OK" {
			panic(vm.ToValue("redis: unexpected AUTH response"))
		}
		info, err := redisCmd(conn, "INFO")
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(info)
	})
	_ = obj.Set("GetServerInfo", func(call goja.FunctionCall) goja.Value {
		host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		info, err := redisInfo(ctx, host, port, "", timeout)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(info)
	})
	_ = obj.Set("GetServerInfoAuth", func(call goja.FunctionCall) goja.Value {
		host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		pass := call.Argument(2).String()
		info, err := redisInfo(ctx, host, port, pass, timeout)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(info)
	})
	_ = obj.Set("Connect", func(call goja.FunctionCall) goja.Value {
		host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		pass := call.Argument(2).String()
		_, err = redisInfo(ctx, host, port, pass, timeout)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(true)
	})
	_ = obj.Set("RunLuaScript", func(call goja.FunctionCall) goja.Value {
		host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		pass := call.Argument(2).String()
		script := call.Argument(3).String()
		out, err := redisEval(ctx, host, port, pass, script, timeout)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(out)
	})
	_ = obj.Set("IsAuthenticated", func(call goja.FunctionCall) goja.Value {
		host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		_, err = redisInfo(ctx, host, port, "", timeout)
		// NOAUTH / need auth → authenticated required
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "auth") {
			return vm.ToValue(true)
		}
		return vm.ToValue(false)
	})
	return obj
}

func redisInfo(ctx context.Context, host string, port int, password string, timeout time.Duration) (string, error) {
	conn, err := redisDial(ctx, host, port, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if password != "" {
		reply, err := redisCmd(conn, "AUTH", password)
		if err != nil {
			return "", err
		}
		if reply != "OK" {
			return "", fmt.Errorf("redis: unexpected AUTH response")
		}
	}
	info, err := redisCmd(conn, "INFO")
	if err == nil && !strings.Contains(info, "redis_version:") {
		err = fmt.Errorf("redis: INFO response has no redis_version")
	}
	return info, err
}

func redisEval(ctx context.Context, host string, port int, password, script string, timeout time.Duration) (string, error) {
	conn, err := redisDial(ctx, host, port, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if password != "" {
		if _, err := redisCmd(conn, "AUTH", password); err != nil {
			return "", err
		}
	}
	return redisCmd(conn, "EVAL", script, "0")
}

func redisDial(ctx context.Context, host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", joinAddr(host, port))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func redisCmd(conn net.Conn, parts ...string) (string, error) {
	var b strings.Builder
	b.WriteString("*")
	b.WriteString(strconv.Itoa(len(parts)))
	b.WriteString("\r\n")
	for _, p := range parts {
		b.WriteString("$")
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteString("\r\n")
		b.WriteString(p)
		b.WriteString("\r\n")
	}
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return "", err
	}
	return redisRead(conn)
}

func redisRead(conn net.Conn) (string, error) {
	r := bufio.NewReader(conn)
	prefix, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	switch prefix {
	case '+':
		return line, nil
	case '-':
		return "", fmt.Errorf("redis: %s", line)
	case ':':
		return line, nil
	case '$':
		n, err := strconv.Atoi(line)
		if err != nil {
			return "", err
		}
		if n < 0 {
			return "", nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(line)
		if err != nil {
			return "", err
		}
		var parts []string
		for i := 0; i < n; i++ {
			s, err := redisRead(conn)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, "\n"), nil
	default:
		return "", fmt.Errorf("redis: unexpected prefix %q", prefix)
	}
}

// CheckRedisPassword checks INFO after AUTH; empty means no AUTH is sent.
func CheckRedisPassword(ctx context.Context, host string, port int, password string, timeout time.Duration) (bool, error) {
	_, err := redisInfo(ctx, host, port, password, timeout)
	return err == nil, err
}
