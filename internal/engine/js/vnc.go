package js

import (
	"context"
	"net"
	"strings"
	"time"

	vnclib "github.com/alexsnet/go-vnc"
	"github.com/dop251/goja"
)

// vncModule exposes VNCClient as a goja constructor — see smbModule's doc
// comment for why a plain FunctionCall-shaped factory isn't enough (real
// templates use `new vnc.VNCClient()`). Was previously a stub with no
// methods at all: unauth-vnc-server-detect.yaml / vnc-default-login.yaml
// failed with "TypeError: Value is not an object: undefined" the moment
// they touched it.
func vncModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	obj := vm.NewObject()
	ctor := func(call goja.ConstructorCall) *goja.Object {
		c := &VNCClient{ctx: ctx, timeout: timeout}
		inst := vm.NewObject()
		_ = inst.Set("Connect", func(call goja.FunctionCall) goja.Value {
			host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			password := call.Argument(2).String()
			ok, err := c.Connect(host, port, password)
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			return vm.ToValue(ok)
		})
		return inst
	}
	_ = obj.Set("VNCClient", ctor)
	return obj
}

// VNCClient mirrors nuclei/vnc.VNCClient, backed by the same third-party RFB
// client real nuclei uses (github.com/alexsnet/go-vnc), not a hand-rolled
// reimplementation of the DES challenge-response handshake.
type VNCClient struct {
	ctx     context.Context
	timeout time.Duration
}

// Connect performs the RFB handshake and, if the server requires
// authentication, tries password. Returns true only on a fully successful
// connection (including the "no authentication required" case real
// unauth-vnc-server-detect.yaml checks for — any password text succeeds
// there since the server never asks for one). A wrong password is a clean
// false, not an error — only a genuine connection/protocol problem is.
// NewVNCClient constructs a VNCClient for direct use outside the goja
// runtime — see ssh.go's NewSSHClient.
func NewVNCClient(ctx context.Context, timeout time.Duration) *VNCClient {
	return &VNCClient{ctx: ctx, timeout: timeout}
}

func (c *VNCClient) Connect(host string, port int, password string) (bool, error) {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(c.ctx, "tcp", joinAddr(host, port))
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	cfg := vnclib.NewClientConfig(password)
	vc, err := vnclib.Connect(c.ctx, conn, cfg)
	if err != nil {
		if isVNCAuthError(err) {
			return false, nil
		}
		return false, err
	}
	if vc != nil {
		_ = vc.Close()
	}
	return true, nil
}

// isVNCAuthError mirrors nuclei's own isAuthError: a wrong password is a
// clean non-match, not a scan error, same substring heuristic.
func isVNCAuthError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	for _, s := range []string{"authentication", "auth", "password", "invalid", "failed"} {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
