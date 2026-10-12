package adscan

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/oiweiwei/go-msrpc/ssp/ntlm"
)

type coercionEvent struct {
	Time            time.Time
	Stage, Identity string
}
type coercionReceiver struct {
	listener    net.Listener
	mu          sync.Mutex
	connections map[net.Conn]bool
	events      map[string][]coercionEvent
	allowed     map[string]bool
	wg          sync.WaitGroup
	cancel      context.CancelFunc
	observe     func(string, coercionEvent)
}

func startCoercionReceiver(parent context.Context, ip string, allowed map[string]bool) (*coercionReceiver, error) {
	l, e := net.Listen("tcp4", net.JoinHostPort(ip, "445"))
	if e != nil {
		return nil, fmt.Errorf("приёмник SMB %s:445: %w (порт должен быть свободен; нужны CAP_NET_BIND_SERVICE или root; см. COERCION.md)", ip, e)
	}
	ctx, cancel := context.WithCancel(parent)
	r := &coercionReceiver{listener: l, connections: map[net.Conn]bool{}, events: map[string][]coercionEvent{}, allowed: allowed, cancel: cancel}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			r.mu.Lock()
			admit := r.allowed[host] && len(r.connections) < 32 && ctx.Err() == nil
			if admit {
				r.connections[c] = true
				r.wg.Add(1)
			}
			r.mu.Unlock()
			if !admit {
				c.Close()
				continue
			}
			go func() {
				defer r.wg.Done()
				defer c.Close()
				defer func() { r.mu.Lock(); delete(r.connections, c); r.mu.Unlock() }()
				r.record(host, "connection", "")
				r.serve(ctx, c, host)
			}()
		}
	}()
	go func() {
		<-ctx.Done()
		l.Close()
		r.mu.Lock()
		for c := range r.connections {
			c.Close()
		}
		r.mu.Unlock()
	}()
	return r, nil
}
func (r *coercionReceiver) close() { r.cancel(); r.listener.Close(); r.wg.Wait() }
func (r *coercionReceiver) record(host, stage, identity string) {
	r.mu.Lock()
	event := coercionEvent{time.Now(), stage, identity}
	stored := len(r.events[host]) < 256
	if stored {
		r.events[host] = append(r.events[host], event)
	}
	observe := r.observe
	r.mu.Unlock()
	if stored && observe != nil {
		observe(host, event)
	}
}
func (r *coercionReceiver) since(host string, t time.Time) []coercionEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []coercionEvent{}
	for _, e := range r.events[host] {
		if !e.Time.Before(t) {
			out = append(out, e)
		}
	}
	return out
}

var le = binary.LittleEndian

func der(tag byte, b []byte) []byte {
	out := []byte{tag}
	n := len(b)
	if n < 128 {
		out = append(out, byte(n))
	} else if n < 256 {
		out = append(out, 0x81, byte(n))
	} else {
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, b...)
}

func spnegoNegotiate() []byte {
	spnegoOID := []byte{6, 6, 0x2b, 6, 1, 5, 5, 2}
	ntlmOID := []byte{6, 10, 0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 2, 10}
	mechTypes := der(0xa0, der(0x30, ntlmOID))
	return der(0x60, append(spnegoOID, der(0xa0, der(0x30, mechTypes))...))
}

func spnegoChallenge(token []byte) []byte {
	oid := []byte{6, 10, 0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 2, 10}
	fields := append(der(0xa0, []byte{0x0a, 1, 1}), der(0xa1, oid)...)
	fields = append(fields, der(0xa2, der(4, token))...)
	return der(0xa1, der(0x30, fields))
}

// ntlmChallenge includes both NetBIOS AV pairs required by NTLMv2 clients
// requesting integrity. WSCAN is the receiver's local authority, not an AD domain.
func ntlmChallenge(ctx context.Context, negotiate []byte) ([]byte, error) {
	a := ntlm.Authentifier{Config: ntlm.NewConfig()}
	a.Config.NetBIOSComputerName = "WSCAN"
	a.Config.DNSComputerName = "wscan.invalid"
	token, err := a.Challenge(ctx, negotiate)
	if err != nil {
		return nil, err
	}
	challenge := &ntlm.ChallengeMessage{}
	if err := challenge.Unmarshal(ctx, token); err != nil {
		return nil, err
	}
	challenge.TargetInfo[ntlm.AttrNetBIOSDomainName] = &ntlm.Value{NetBIOSDomainName: "WSCAN"}
	return challenge.Marshal(ctx)
}

func smbRead(c net.Conn) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return nil, e
	}
	if h[0] != 0 {
		return nil, fmt.Errorf("unsupported framing")
	}
	n := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	if n < 64 || n > 65536 {
		return nil, fmt.Errorf("invalid SMB length")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(c, b)
	return b, e
}
func smbWrite(c net.Conn, b []byte) error {
	h := []byte{0, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	for _, v := range [][]byte{h, b} {
		for len(v) > 0 {
			n, e := c.Write(v)
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			v = v[n:]
		}
	}
	return nil
}
func smbResponse(request []byte, command uint16, status uint32, session uint64, body []byte) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0xfe, 'S', 'M', 'B'})
	le.PutUint16(h[4:], 64)
	le.PutUint32(h[8:], status)
	le.PutUint16(h[12:], command)
	le.PutUint16(h[14:], 1)
	le.PutUint32(h[16:], 1)
	if len(request) >= 64 {
		copy(h[24:32], request[24:32])
		copy(h[32:36], request[32:36])
	}
	le.PutUint64(h[40:], session)
	return append(h, body...)
}
func (r *coercionReceiver) serve(ctx context.Context, c net.Conn, host string) {
	c.SetDeadline(time.Now().Add(12 * time.Second))
	var sessionBytes [8]byte
	if _, e := rand.Read(sessionBytes[:]); e != nil {
		return
	}
	session := le.Uint64(sessionBytes[:]) | 1
	negotiated, challenged := false, false
	for step := 0; step < 6; step++ {
		b, e := smbRead(c)
		if e != nil {
			if challenged {
				r.record(host, "incomplete-auth", "соединение завершилось после NTLM challenge: "+e.Error())
			}
			return
		}
		// SMB1 multi-protocol negotiate is answered with wildcard SMB2, inviting
		// a proper SMB2 negotiate. SMB1 sessions are not implemented.
		if bytes.Equal(b[:4], []byte{0xff, 'S', 'M', 'B'}) {
			if b[4] != 0x72 {
				return
			}
			body := make([]byte, 64)
			le.PutUint16(body, 65)
			le.PutUint16(body[4:], 0x02ff)
			if smbWrite(c, smbResponse(nil, 0, 0, 0, body)) != nil {
				return
			}
			continue
		}
		if !bytes.Equal(b[:4], []byte{0xfe, 'S', 'M', 'B'}) || le.Uint16(b[4:]) != 64 || le.Uint32(b[20:]) != 0 {
			return
		}
		command := le.Uint16(b[12:])
		switch command {
		case 0:
			if len(b) < 100 || le.Uint16(b[64:]) != 36 {
				return
			}
			count := int(le.Uint16(b[66:]))
			if count < 1 || count > 64 || 100+2*count > len(b) {
				return
			}
			dialect := uint16(0)
			for i := 0; i < count; i++ {
				d := le.Uint16(b[100+i*2:])
				if d == 0x210 {
					dialect = d
				}
				if d == 0x202 && dialect == 0 {
					dialect = d
				}
			}
			if dialect == 0 {
				r.record(host, "unsupported-dialect", "SMB 2.0.2/2.1 отсутствует; результат неполный")
				return
			}
			// SPNEGO NegTokenInit advertising only the NTLM mechanism.
			token := spnegoNegotiate()
			body := make([]byte, 64)
			le.PutUint16(body, 65)
			le.PutUint16(body[2:], 1)
			le.PutUint16(body[4:], dialect)
			if _, e = rand.Read(body[8:24]); e != nil {
				return
			}
			for _, off := range []int{28, 32, 36} {
				le.PutUint32(body[off:], 65536)
			}
			le.PutUint64(body[40:], uint64(time.Now().UnixNano()/100)+116444736000000000)
			le.PutUint16(body[56:], 128)
			le.PutUint16(body[58:], uint16(len(token)))
			if smbWrite(c, smbResponse(b, 0, 0, 0, append(body, token...))) != nil {
				return
			}
			negotiated = true
			r.record(host, "smb-negotiated", fmt.Sprintf("dialect %#x", dialect))
		case 1:
			if !negotiated || len(b) < 88 || le.Uint16(b[64:]) != 25 {
				return
			}
			off, n := int(le.Uint16(b[76:])), int(le.Uint16(b[78:]))
			if off < 88 || n < 12 || off+n > len(b) {
				return
			}
			token := b[off : off+n]
			index := bytes.Index(token, []byte("NTLMSSP\x00"))
			if index < 0 {
				return
			}
			token = token[index:]
			if len(token) < 12 {
				return
			}
			switch le.Uint32(token[8:]) {
			case 1:
				if challenged {
					return
				}
				challenge, e := ntlmChallenge(ctx, token)
				if e != nil {
					return
				}
				challenge = spnegoChallenge(challenge)
				body := make([]byte, 8)
				le.PutUint16(body, 9)
				le.PutUint16(body[4:], 72)
				le.PutUint16(body[6:], uint16(len(challenge)))
				if smbWrite(c, smbResponse(b, 1, 0xc0000016, session, append(body, challenge...))) != nil {
					return
				}
				challenged = true
				r.record(host, "ntlm-negotiate", "")
			case 3:
				if !challenged || le.Uint64(b[40:]) != session || len(token) < 64 {
					return
				}
				// Extract only identity, never retain challenge responses or a crackable hash.
				identity, e := ntlmIdentity(token)
				if e != nil {
					stage := "invalid-authenticate"
					if errors.Is(e, errAnonymousNTLM) {
						stage = "anonymous-authenticate"
					}
					r.record(host, stage, e.Error())
					smbWrite(c, smbResponse(b, 1, 0xc000006d, session, []byte{9, 0, 0, 0, 0, 0, 0, 0}))
					return
				}
				r.record(host, "ntlm-authenticate", identity)
				smbWrite(c, smbResponse(b, 1, 0xc000006d, session, []byte{9, 0, 0, 0, 0, 0, 0, 0}))
				return
			default:
				return
			}
		default:
			return
		}
	}
}

var errAnonymousNTLM = errors.New("анонимный NTLM Authenticate: имя пользователя и NTLM-ответ отсутствуют; учётные данные не получены")

func ntlmIdentity(token []byte) (string, error) {
	if len(token) < 64 || !bytes.Equal(token[:8], []byte("NTLMSSP\x00")) || le.Uint32(token[8:]) != 3 {
		return "", fmt.Errorf("invalid NTLM authenticate header")
	}
	// Validate every response and identity security buffer before reading any.
	for _, off := range []int{12, 20, 28, 36, 44, 52} {
		n := int(le.Uint16(token[off:]))
		p := uint64(le.Uint32(token[off+4:]))
		if n > 0 && (p < 64 || p+uint64(n) > uint64(len(token))) {
			return "", fmt.Errorf("NTLM security buffer outside message")
		}
	}
	field := func(off int) (string, error) {
		n := int(le.Uint16(token[off:]))
		p := int(le.Uint32(token[off+4:]))
		if n == 0 {
			return "", nil
		}
		raw := token[p : p+n]
		if le.Uint32(token[60:])&1 == 0 {
			return string(raw), nil
		}
		if n%2 != 0 {
			return "", fmt.Errorf("invalid Unicode length")
		}
		u := make([]uint16, n/2)
		for i := range u {
			u[i] = le.Uint16(raw[i*2:])
		}
		return string(utf16.Decode(u)), nil
	}
	domain, e := field(28)
	if e != nil {
		return "", e
	}
	user, e := field(36)
	if e != nil {
		return "", e
	}
	workstation, e := field(44)
	if e != nil {
		return "", e
	}
	if user == "" && le.Uint16(token[20:]) == 0 && le.Uint16(token[12:]) <= 1 {
		return "", errAnonymousNTLM
	}
	if user == "" || le.Uint16(token[20:]) < 24 {
		return "", fmt.Errorf("неполный NTLM Authenticate: отсутствует имя или полноценный NTLM-ответ")
	}
	return fmt.Sprintf("identity=%q\\%q workstation=%q (заявлено клиентом)", domain, user, workstation), nil
}
