package smbidentity

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Identity comes only from an unauthenticated NTLM challenge. No Type 3
// message, password, share access or command is sent by this probe.
type Identity struct {
	MachineRole     *int   `json:"machine_role,omitempty"`
	RoleSource      string `json:"role_source,omitempty"`
	ComputerName    string `json:"computer_name"`
	DomainName      string `json:"domain_name,omitempty"`
	DNSComputerName string `json:"dns_computer_name,omitempty"`
	DNSDomainName   string `json:"dns_domain_name,omitempty"`
	ForestName      string `json:"forest_name,omitempty"`
	TargetName      string `json:"target_name,omitempty"`
	TargetIsDomain  bool   `json:"target_is_domain"`
	TargetIsServer  bool   `json:"target_is_server"`
	OSVersion       string `json:"os_version,omitempty"`
	SigningRequired bool   `json:"signing_required"`
}

func readSMBFrame(r io.Reader) ([]byte, error) {
	h := make([]byte, 4)
	if _, e := io.ReadFull(r, h); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint32(h))
	if n < 64 || n > 65536 {
		return nil, fmt.Errorf("invalid SMB frame size %d", n)
	}
	packet := make([]byte, 4+n)
	copy(packet, h)
	_, e := io.ReadFull(r, packet[4:])
	return packet, e
}

func Probe(ctx context.Context, host string, port int, timeout time.Duration) (Identity, error) {
	var result Identity
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if e != nil {
		return result, e
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	if _, e = c.Write(smbNegotiatePacket()); e != nil {
		return result, e
	}
	packet, e := readSMBFrame(c)
	if e != nil {
		return result, e
	}
	if len(packet) < 74 || !bytes.Equal(packet[4:8], []byte{0xfe, 'S', 'M', 'B'}) {
		return result, fmt.Errorf("SMB2 negotiate not returned")
	}
	signing := binary.LittleEndian.Uint16(packet[70:72])&2 != 0
	if _, e = c.Write(smbSessionSetupPacket()); e != nil {
		return result, e
	}
	packet, e = readSMBFrame(c)
	if e != nil {
		return result, e
	}
	if len(packet) < 76 || !bytes.Equal(packet[4:8], []byte{0xfe, 'S', 'M', 'B'}) {
		return result, fmt.Errorf("SMB2 challenge not returned")
	}
	start := 4 + int(binary.LittleEndian.Uint16(packet[72:74]))
	end := start + int(binary.LittleEndian.Uint16(packet[74:76]))
	if start < 76 || end > len(packet) || end <= start {
		return result, fmt.Errorf("invalid SMB security buffer")
	}
	result, e = Parse(packet[start:end])
	result.SigningRequired = signing
	return result, e
}

func Parse(blob []byte) (Identity, error) {
	var r Identity
	i := bytes.Index(blob, []byte("NTLMSSP\x00"))
	if i < 0 {
		return r, fmt.Errorf("NTLM challenge absent")
	}
	b := blob[i:]
	if len(b) < 48 || binary.LittleEndian.Uint32(b[8:12]) != 2 {
		return r, fmt.Errorf("invalid NTLM challenge")
	}
	decode := func(data []byte) (string, error) {
		if len(data)%2 != 0 {
			return "", fmt.Errorf("odd NTLM Unicode string length")
		}
		chars := make([]uint16, len(data)/2)
		for j := range chars {
			chars[j] = binary.LittleEndian.Uint16(data[j*2:])
		}
		s := string(utf16.Decode(chars))
		if strings.ContainsAny(s, "\x00\r\n") {
			return "", fmt.Errorf("invalid NTLM identity characters")
		}
		return s, nil
	}
	buffer := func(off int) ([]byte, error) {
		n := int(binary.LittleEndian.Uint16(b[off : off+2]))
		start := uint64(binary.LittleEndian.Uint32(b[off+4 : off+8]))
		if start+uint64(n) > uint64(len(b)) {
			return nil, fmt.Errorf("invalid NTLM buffer offset")
		}
		return b[int(start) : int(start)+n], nil
	}
	flags := binary.LittleEndian.Uint32(b[20:24])
	r.TargetIsDomain = flags&0x10000 != 0
	r.TargetIsServer = flags&0x20000 != 0
	target, e := buffer(12)
	if e != nil {
		return r, e
	}
	if flags&1 != 0 {
		r.TargetName, e = decode(target)
	} else {
		r.TargetName = string(target)
	}
	if e != nil {
		return r, e
	}
	if len(b) >= 56 && flags&ntlmVersionFlag != 0 {
		r.OSVersion = fmt.Sprintf("%d.%d.%d", b[48], b[49], binary.LittleEndian.Uint16(b[50:52]))
	}
	info, e := buffer(40)
	if e != nil {
		return r, e
	}
	for len(info) >= 4 {
		kind, n := binary.LittleEndian.Uint16(info[:2]), int(binary.LittleEndian.Uint16(info[2:4]))
		info = info[4:]
		if n > len(info) {
			return r, fmt.Errorf("truncated NTLM AV pair")
		}
		if kind == 0 {
			if n != 0 {
				return r, fmt.Errorf("invalid NTLM AV terminator")
			}
			return r, nil
		}
		if kind >= 1 && kind <= 5 {
			s, e := decode(info[:n])
			if e != nil {
				return r, e
			}
			switch kind {
			case 1:
				r.ComputerName = s
			case 2:
				r.DomainName = s
			case 3:
				r.DNSComputerName = s
			case 4:
				r.DNSDomainName = s
			case 5:
				r.ForestName = s
			}
		}
		info = info[n:]
	}
	if len(info) != 0 {
		return r, fmt.Errorf("truncated NTLM AV header")
	}
	return r, nil
}

func smbNegotiatePacket() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0311}
	bodyLen := 36 + len(dialects)*2
	pkt := make([]byte, 4+64+bodyLen)
	binary.BigEndian.PutUint32(pkt[0:4], uint32(64+bodyLen))
	copy(pkt[4:8], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[8:10], 64) // StructureSize
	binary.LittleEndian.PutUint16(pkt[16:18], 0) // Command = NEGOTIATE
	binary.LittleEndian.PutUint32(pkt[28:32], 0) // MessageId = 0
	binary.LittleEndian.PutUint32(pkt[36:40], 0xFEFF)
	off := 68
	binary.LittleEndian.PutUint16(pkt[off:off+2], 36) // StructureSize
	binary.LittleEndian.PutUint16(pkt[off+2:off+4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(pkt[off+4:off+6], 1) // SecurityMode: signing enabled
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(pkt[off+36+i*2:off+36+i*2+2], d)
	}
	return pkt
}

func ntlmNegotiateMessage() []byte {
	const flags = 0x00000001 | 0x00000004 | 0x00000200 | 0x00080000 | ntlmVersionFlag | 0x20000000 | 0x80000000
	msg := make([]byte, 40)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 1) // MessageType = NEGOTIATE
	binary.LittleEndian.PutUint32(msg[12:16], flags)
	binary.LittleEndian.PutUint32(msg[20:24], 40) // DomainNameBufferOffset (zero-length)
	binary.LittleEndian.PutUint32(msg[28:32], 40) // WorkstationBufferOffset (zero-length)
	msg[32] = 10                                  // claimed ProductMajorVersion (informational only)
	msg[33] = 0
	binary.LittleEndian.PutUint16(msg[34:36], 19041)
	msg[39] = 15 // NTLMRevisionCurrent
	return msg
}

func smbSessionSetupPacket() []byte {
	ntlm := ntlmNegotiateMessage()
	const fixedBody = 24 // StructureSize+Flags+SecurityMode+Capabilities+Channel+SecBufOffset+SecBufLen+PreviousSessionId
	bodyLen := fixedBody + len(ntlm)
	pkt := make([]byte, 4+64+bodyLen)
	binary.BigEndian.PutUint32(pkt[0:4], uint32(64+bodyLen))
	copy(pkt[4:8], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[8:10], 64) // StructureSize
	binary.LittleEndian.PutUint16(pkt[16:18], 1) // Command = SESSION_SETUP
	binary.LittleEndian.PutUint32(pkt[28:32], 1) // MessageId = 1 (NEGOTIATE used 0)
	binary.LittleEndian.PutUint32(pkt[36:40], 0xFEFF)
	off := 68
	binary.LittleEndian.PutUint16(pkt[off:off+2], 25) // StructureSize
	pkt[off+3] = 1                                    // SecurityMode: signing enabled
	secOff := 64 + fixedBody                          // relative to the start of the SMB2 header
	binary.LittleEndian.PutUint16(pkt[off+12:off+14], uint16(secOff))
	binary.LittleEndian.PutUint16(pkt[off+14:off+16], uint16(len(ntlm)))
	copy(pkt[4+64+fixedBody:], ntlm)
	return pkt
}

const ntlmVersionFlag = 0x02000000
