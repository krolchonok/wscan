package js

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var ErrRDPNLARequired = errors.New("RDP requires NLA; unauthenticated vulnerability probe unavailable")
var errRDPStandardRequired = errors.New("RDP requires standard security")
var errRDPTLSRequired = errors.New("RDP requires TLS")

// rdpWire reads complete transport frames. TCP reads are not RDP packets.
type rdpWire struct {
	net.Conn
	ctx context.Context
}

func openRDPWire(parent context.Context, host string, port int, timeout time.Duration, protocols uint32) (*rdpWire, uint32, func(), error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", joinAddr(host, port))
	if err != nil {
		cancel()
		return nil, 0, nil, err
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	close := func() { stop(); _ = conn.Close(); cancel() }
	w := &rdpWire{Conn: conn, ctx: ctx}
	request := []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(request[15:], protocols)
	if err = w.send(request); err != nil {
		close()
		return nil, 0, nil, err
	}
	response, err := w.frame()
	if err != nil {
		close()
		return nil, 0, nil, fmt.Errorf("RDP negotiation: %w", err)
	}
	if len(response) < 11 || response[0] != 3 || response[5] != 0xd0 {
		close()
		return nil, 0, nil, fmt.Errorf("invalid RDP connection confirm")
	}
	if len(response) != 11 && len(response) != 19 {
		close()
		return nil, 0, nil, fmt.Errorf("truncated or unexpected RDP negotiation response")
	}
	var selected uint32
	if len(response) >= 19 {
		if binary.LittleEndian.Uint16(response[13:15]) != 8 {
			close()
			return nil, 0, nil, fmt.Errorf("invalid RDP negotiation length")
		}
		value := binary.LittleEndian.Uint32(response[15:19])
		if response[11] == 3 {
			close()
			if value == 2 {
				return nil, 0, nil, errRDPStandardRequired
			}
			if value == 1 {
				return nil, 0, nil, errRDPTLSRequired
			}
			if value == 5 || value == 6 {
				return nil, 0, nil, ErrRDPNLARequired
			}
			return nil, 0, nil, fmt.Errorf("RDP negotiation rejected: %d", value)
		}
		if response[11] != 2 {
			close()
			return nil, 0, nil, fmt.Errorf("invalid RDP negotiation type")
		}
		selected = value
	}
	if selected == 2 || selected == 8 {
		close()
		return nil, 0, nil, ErrRDPNLARequired
	}
	if selected != 0 && selected != 1 {
		close()
		return nil, 0, nil, fmt.Errorf("unsupported RDP security protocol %d", selected)
	}
	if selected == 1 {
		t := tls.Client(conn, &tls.Config{
			// This is a diagnostic connection to legacy, usually self-signed RDP.
			InsecureSkipVerify: true, MinVersion: tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		})
		if err = t.HandshakeContext(ctx); err != nil {
			close()
			return nil, 0, nil, fmt.Errorf("RDP TLS: %w", err)
		}
		w.Conn = t
	}
	return w, selected, close, nil
}

func (w *rdpWire) send(data []byte) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (w *rdpWire) frame() ([]byte, error) {
	if err := w.ctx.Err(); err != nil {
		return nil, err
	}
	h := make([]byte, 2)
	if _, err := io.ReadFull(w, h); err != nil {
		return nil, err
	}
	var length int
	if h[0] == 3 {
		if h[1] != 0 {
			return nil, fmt.Errorf("invalid TPKT header")
		}
		h = append(h, 0, 0)
		if _, err := io.ReadFull(w, h[2:]); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint16(h[2:]))
	} else { // RDP fast-path packets can arrive between slow-path packets.
		length = int(h[1])
		if h[1]&0x80 != 0 {
			h = append(h, 0)
			if _, err := io.ReadFull(w, h[2:]); err != nil {
				return nil, err
			}
			length = int(h[1]&0x7f)<<8 | int(h[2])
		}
	}
	if length < len(h) || length > 65535 {
		return nil, fmt.Errorf("invalid RDP frame length %d", length)
	}
	p := make([]byte, length)
	copy(p, h)
	_, err := io.ReadFull(w, p[len(h):])
	return p, err
}

func rdpTPDU(data []byte) []byte {
	p := make([]byte, 7, 7+len(data))
	p[0], p[4], p[5], p[6] = 3, 2, 0xf0, 0x80
	binary.BigEndian.PutUint16(p[2:], uint16(7+len(data)))
	return append(p, data...)
}

func rdpJoinRequest(user, channel uint16) []byte {
	b := make([]byte, 5)
	b[0] = 0x38
	binary.BigEndian.PutUint16(b[1:], user)
	binary.BigEndian.PutUint16(b[3:], channel)
	return rdpTPDU(b)
}

func (w *rdpWire) mcsFrame(command byte) ([]byte, error) {
	for i := 0; i < 32; i++ {
		p, err := w.frame()
		if err != nil {
			return nil, err
		}
		if len(p) >= 8 && p[0] == 3 && p[5] == 0xf0 && p[6] == 0x80 && p[7] == command {
			return p, nil
		}
		if len(p) >= 9 && p[7] == 0x21 {
			return nil, fmt.Errorf("RDP server disconnected")
		}
	}
	return nil, fmt.Errorf("expected MCS response %02x was not received", command)
}
