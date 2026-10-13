package js

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func rdpTestServer(t *testing.T, serve func(*rdpWire) error) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { ln.Close(); <-done })
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		if err := serve(&rdpWire{Conn: c, ctx: context.Background()}); err != nil {
			t.Errorf("test RDP server: %v", err)
		}
	}()
	host, ps, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(ps)
	return host, port
}

func rdpTestNegotiate(w *rdpWire, response []byte) error {
	p, err := w.frame()
	if err != nil {
		return err
	}
	if len(p) != 19 || p[5] != 0xe0 {
		return fmt.Errorf("bad negotiation request")
	}
	for _, b := range response {
		if err := w.send([]byte{b}); err != nil {
			return err
		}
	}
	return nil
}

func rdpTestConfirm(protocol uint32) []byte {
	b := []byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[15:], protocol)
	return b
}

func TestRDPChecksReportNLAAndInvalidResponses(t *testing.T) {
	for _, check := range []func(context.Context, string, int, time.Duration) (bool, error){CheckMS12020, CheckBlueKeep} {
		for _, response := range [][]byte{rdpTestConfirm(2), {3, 0, 0, 11, 6, 0x10, 0, 0, 0, 0, 0}} {
			h, p := rdpTestServer(t, func(w *rdpWire) error { return rdpTestNegotiate(w, response) })
			v, err := check(context.Background(), h, p, time.Second)
			if v || err == nil {
				t.Fatal("NLA or invalid protocol was classified as a successful negative check")
			}
			if len(response) == 19 && !errors.Is(err, ErrRDPNLARequired) {
				t.Fatalf("NLA status lost: %v", err)
			}
		}
	}
}

func TestMS12020UsesChannelOwnersAndCleanup(t *testing.T) {
	for _, patched := range []bool{false, true} {
		h, p := rdpTestServer(t, func(w *rdpWire) error {
			if err := rdpTestNegotiate(w, rdpTestConfirm(0)); err != nil {
				return err
			}
			initial, err := w.frame()
			if err != nil {
				return err
			}
			if !bytes.Contains(initial, []byte("Duca")) || bytes.Contains(initial, []byte("MS_T120")) {
				return fmt.Errorf("missing GCC or unrelated MS_T120 channel in MS12 probe")
			}
			// A Connect Response precedes Attach User Confirm on the same TCP stream.
			if err := w.send(rdpTPDU([]byte{0x7f, 0x66, 0})); err != nil {
				return err
			}
			erect, err := w.frame()
			if err != nil {
				return err
			}
			if !bytes.Equal(erect, rdpTPDU([]byte{4, 1, 0, 1, 0})) {
				return fmt.Errorf("missing Erect Domain request before attach")
			}
			for _, u := range []uint16{42, 300} {
				req, err := w.frame()
				if err != nil {
					return err
				}
				if len(req) != 8 || req[7] != 0x28 {
					return fmt.Errorf("bad attach")
				}
				b := []byte{0x2e, 0, 0, 0}
				binary.BigEndian.PutUint16(b[2:], u)
				if err := w.send(rdpTPDU(b)); err != nil {
					return err
				}
			}
			req, err := w.frame()
			if err != nil {
				return err
			}
			if len(req) != 12 || binary.BigEndian.Uint16(req[8:]) != 42 || binary.BigEndian.Uint16(req[10:]) != 1301 {
				return fmt.Errorf("wrong cross-user channel join")
			}
			b := []byte{0x3e, 0, 0, 42, 5, 21, 5, 21}
			if patched {
				b[1] = 6
			}
			if err := w.send(rdpTPDU(b)); err != nil {
				return err
			}
			if !patched {
				cleanup, err := w.frame()
				if err != nil {
					return err
				}
				if binary.BigEndian.Uint16(cleanup[8:]) != 300 || binary.BigEndian.Uint16(cleanup[10:]) != 1301 {
					return fmt.Errorf("cleanup did not use rightful owner")
				}
				binary.BigEndian.PutUint16(b[2:], 300)
				return w.send(rdpTPDU(b))
			}
			return nil
		})
		v, err := CheckMS12020(context.Background(), h, p, time.Second)
		if err != nil || v == patched {
			t.Fatalf("patched=%v vulnerable=%v err=%v", patched, v, err)
		}
	}
}

func rdpTestServerData(data []byte) []byte {
	b := []byte{0x68, 0, 42, 3, 0xeb, 0x70}
	if len(data) < 128 {
		b = append(b, byte(len(data)))
	} else {
		b = append(b, byte(len(data)>>8)|0x80, byte(len(data)))
	}
	return rdpTPDU(append(b, data...))
}

func TestBlueKeepRequiresActivatedSessionAndExactProbeResponse(t *testing.T) {
	tlsFixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsFixture.Close()
	for _, useTLS := range []bool{false, true} {
		for _, vulnerable := range []bool{false, true} {
			h, p := rdpTestServer(t, func(w *rdpWire) error {
				proto := uint32(0)
				if useTLS {
					proto = 1
				}
				if err := rdpTestNegotiate(w, rdpTestConfirm(proto)); err != nil {
					return err
				}
				if useTLS {
					c := tls.Server(w.Conn, tlsFixture.TLS.Clone())
					if err := c.Handshake(); err != nil {
						return err
					}
					w.Conn = c
				}
				initial, err := w.frame()
				if err != nil {
					return err
				}
				if !bytes.Contains(initial, []byte("MS_T120")) {
					return fmt.Errorf("MS_T120 was not requested")
				}
				blocks := []byte{1, 12, 8, 0, 4, 0, 8, 0, 2, 12, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 12, 20, 0, 0xeb, 3, 5, 0}
				for id := uint16(2001); id <= 2005; id++ {
					b := make([]byte, 2)
					binary.LittleEndian.PutUint16(b, id)
					blocks = append(blocks, b...)
				}
				blocks = append(blocks, 0, 0)
				if err := w.send(rdpTPDU(append([]byte{0x7f, 0x66}, blocks...))); err != nil {
					return err
				}
				if _, err := w.frame(); err != nil {
					return err
				}
				if _, err := w.frame(); err != nil {
					return err
				}
				if err := w.send(rdpTPDU([]byte{0x2e, 0, 0, 42})); err != nil {
					return err
				}
				for _, id := range []uint16{1043, 1003, 2001, 2002, 2003, 2004, 2005} {
					join, err := w.frame()
					if err != nil {
						return err
					}
					if binary.BigEndian.Uint16(join[8:]) != 42 || binary.BigEndian.Uint16(join[10:]) != id {
						return fmt.Errorf("wrong channel/user")
					}
					b := []byte{0x3e, 0, 0, 42, 0, 0, 0, 0}
					binary.BigEndian.PutUint16(b[4:], id)
					binary.BigEndian.PutUint16(b[6:], id)
					if err := w.send(rdpTPDU(b)); err != nil {
						return err
					}
				}
				info, err := w.frame()
				if err != nil {
					return err
				}
				if !bytes.Contains(info, []byte{0x40, 0, 0, 0}) {
					return fmt.Errorf("missing client info")
				}
				license := []byte{0x80, 0, 0, 0, 0xff, 3, 16, 0, 7, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0}
				if err := w.send(rdpTestServerData(license)); err != nil {
					return err
				}
				demand := make([]byte, 0x188)
				copy(demand, []byte{0x88, 1, 0x11, 0, 0xea, 3, 0x78, 0x56, 0x34, 0x12})
				if err := w.send(rdpTestServerData(demand)); err != nil {
					return err
				}
				for i := 0; i < 6; i++ {
					if _, err := w.frame(); err != nil {
						return err
					}
				}
				fontmap := make([]byte, 18)
				fontmap[0] = 18
				fontmap[2] = 0x17
				fontmap[14] = 0x28
				if err := w.send(rdpTestServerData(fontmap)); err != nil {
					return err
				}
				for _, size := range []int{16, 32} {
					probe, err := w.frame()
					if err != nil {
						return err
					}
					if binary.BigEndian.Uint16(probe[10:]) != 2002 {
						return fmt.Errorf("MS_T120 server-assigned channel not used")
					}
					data := probe[15:]
					if len(data) != size+8 || binary.LittleEndian.Uint32(data) != uint32(size) || binary.LittleEndian.Uint32(data[4:]) != 3 || binary.LittleEndian.Uint32(data[8+size/4:]) != 2 {
						return fmt.Errorf("invalid or oversized check-only channel probe")
					}
				}
				if vulnerable {
					return w.send([]byte{3, 0, 0, 9, 2, 0xf0, 0x80, 0x21, 0x80})
				}
				// EOF after sending probes cannot establish that a target is patched.
				return nil
			})
			v, err := CheckBlueKeep(context.Background(), h, p, 3*time.Second)
			if vulnerable && (!v || err != nil) || !vulnerable && (v || err == nil) {
				t.Fatalf("TLS=%v vulnerable=%v got=%v err=%v", useTLS, vulnerable, v, err)
			}
		}
	}
}

func TestRDPChecksStopOnCancellation(t *testing.T) {
	h, p := rdpTestServer(t, func(w *rdpWire) error { _, _ = w.frame(); time.Sleep(100 * time.Millisecond); return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	v, err := CheckBlueKeep(ctx, h, p, time.Second)
	if v || err == nil || time.Since(start) > 500*time.Millisecond {
		t.Fatal("cancelled probe did not stop promptly")
	}
}
