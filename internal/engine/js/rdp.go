package js

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/dop251/goja"
)

// rdpModule exposes IsRDP — the one nuclei/rdp function a real template uses
// (rdp-detect.yaml). Was a bare stub with zero methods: `m.IsRDP` threw
// "Object has no member 'IsRDP'" on every run. Mirrors fingerprintx's
// rdp.DetectRDP (what nuclei's own IsRDP is backed by): send the fixed
// X.224/RDP Negotiation Request nuclei/fingerprintx send, and check the
// response against the generic RDP signature and a table of OS-specific
// ones — pure byte matching, no protocol state machine needed.
func rdpModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	obj := vm.NewObject()
	_ = obj.Set("IsRDP", func(call goja.FunctionCall) goja.Value {
		host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		resp, err := isRDP(ctx, host, port, timeout)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(resp)
	})
	return obj
}

// IsRDPResponse mirrors nuclei/rdp.IsRDPResponse field-for-field (field
// names, not json tags — see smbModule's doc comment for why).
type IsRDPResponse struct {
	IsRDP bool   `json:"IsRDP"`
	OS    string `json:"OS"`
}

// rdpNegotiationRequest is the exact probe fingerprintx's rdp.DetectRDP
// sends: an X.224 Connection Request wrapping an RDP Negotiation Request
// (type 0x01, no flags, protocol flags = PROTOCOL_SSL|PROTOCOL_HYBRID).
var rdpNegotiationRequest = []byte{
	0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0b,
	0x00, 0x00, 0x00,
}

// rdpGenericSignature is the X.224 Connection Confirm prefix every real RDP
// server's response starts with, regardless of OS.
var rdpGenericSignature = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00}

// rdpOSSignatures are fingerprintx's per-OS response prefixes (the
// negotiated RDP_NEG_RSP selectedProtocol/flags byte sequence differs by
// Windows version).
var rdpOSSignatures = map[string][]byte{
	"Windows 2000": {
		0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	},
	"Windows Server 2003": {
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	},
	"Windows Server 2008": {
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	},
	"Windows 7 or Server 2008 R2": {
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x09, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	},
	"Windows Server 2008 R2 DC": {
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	},
	"Windows 10": {
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x1f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	},
	"Windows 8 or Server 2012": {
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x0f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	},
	"Windows Server 2016 or 2019": {
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x1f, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00,
	},
}

func isRDP(ctx context.Context, host string, port int, timeout time.Duration) (*IsRDPResponse, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", joinAddr(host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(rdpNegotiationRequest); err != nil {
		return nil, err
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	resp := buf[:n]
	if n == 0 {
		return nil, fmt.Errorf("rdp: empty response")
	}
	if len(resp) < len(rdpGenericSignature) || !bytes.Equal(resp[:len(rdpGenericSignature)], rdpGenericSignature) {
		// Matches real nuclei: a non-RDP response is an error here, not a
		// quiet false — rdp-detect.yaml's own matchers only ever see the
		// success path.
		return nil, fmt.Errorf("rdp: unexpected response")
	}
	out := &IsRDPResponse{IsRDP: true}
	for name, sig := range rdpOSSignatures {
		if len(resp) >= len(sig) && bytes.Equal(resp[:len(sig)], sig) {
			out.OS = name
			break
		}
	}
	return out, nil
}
