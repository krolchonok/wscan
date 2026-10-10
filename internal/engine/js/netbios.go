package js

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// nbstatQuery is a standard NBSTAT wildcard ("*<00>") name query — the exact
// same bytes as library/nuclei-templates/javascript/udp/detection/
// netbios-udp-detect.yaml's already-verified payload (RFC 1002 §4.2.1 name
// encoding + §4.2.17 NODE STATUS REQUEST: QDCOUNT=1, QTYPE=NBSTAT (0x21),
// QCLASS=IN (0x0001), first-level-encoded "*" name zero-padded to 16 bytes).
var nbstatQuery = []byte{
	0x80, 0xf0, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00,
	0x21, 0x00, 0x01,
}

// ResolveNetBIOSName queries the NetBIOS Name Service (RFC 1002 NBSTAT, UDP
// port 137 in real usage — parameterized here for testability) for the
// target's own NetBIOS computer name: the <00> "Workstation Service" unique
// name, the conventional stand-in for the machine's hostname. Some RPC calls
// (notably Zerologon's NetrServerAuthenticate3 — see dcerpc.go) require
// addressing the target by this name; an IP address is rejected.
func ResolveNetBIOSName(ctx context.Context, host string, port int, timeout time.Duration) (string, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", joinAddr(host, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(nbstatQuery); err != nil {
		return "", err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return parseNBSTATResponse(buf[:n])
}

// parseNBSTATResponse extracts the <00> unique (non-group) NetBIOS name from
// a NODE STATUS RESPONSE (RFC 1002 §4.2.18). The query's own encoded name
// echoed back as RR_NAME is always exactly 34 bytes (1 length byte + 32
// first-level-encoded bytes + 1 terminator) for any 16-byte NetBIOS name,
// including this query's "*" wildcard, so the node name array's offset from
// the fixed 12-byte header never varies.
func parseNBSTATResponse(b []byte) (string, error) {
	const headerLen = 12
	const rrNameLen = 34
	const rrFixedLen = 2 + 2 + 4 + 2                      // RR_TYPE + RR_CLASS + TTL + RDLENGTH
	const entryLen = 18                                   // 15-byte name + 1 suffix + 2 flags
	namesOffset := headerLen + rrNameLen + rrFixedLen + 1 /* NUM_NAMES byte */
	if len(b) < namesOffset {
		return "", fmt.Errorf("nbstat: response too short (%d bytes)", len(b))
	}
	numNames := int(b[namesOffset-1])
	for i := 0; i < numNames; i++ {
		off := namesOffset + i*entryLen
		if off+entryLen > len(b) {
			break
		}
		name := strings.TrimRight(string(b[off:off+15]), " ")
		suffix := b[off+15]
		flags := binary.BigEndian.Uint16(b[off+16 : off+18])
		isGroup := flags&0x8000 != 0
		if suffix == 0x00 && !isGroup && name != "" {
			return name, nil
		}
	}
	return "", fmt.Errorf("nbstat: no unique <00> workstation name found")
}
