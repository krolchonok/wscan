package discovery

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"wscan/internal/domain"
)

// identifySMB performs an active, unauthenticated, read-only SMB2
// NEGOTIATE + SESSION_SETUP probe on an already-open connection — the same
// technique nmap's -sV / OS-fingerprint probes use to recognize SMB on
// non-standard ports and read the target's Windows build from the NTLM
// CHALLENGE message's Version field, without valid credentials or any
// state-changing SMB operation (no logon ever completes: the server reply
// to our bare NTLM NEGOTIATE is read and then the connection is dropped by
// the caller).
//
// This exists because identifyService's normal path only reads a banner the
// peer sends unprompted (readBanner) — SMB never speaks first, so a port
// running SMB on a non-standard port (e.g. 4445) was silently left
// unidentified (Name == "") forever, which with OnlyKnownServices also drops
// it from results entirely. nmap's own -sV calls this out by name
// ("microsoft-ds") plus an OS line on the exact same probe.
func identifySMB(conn net.Conn, service domain.Service, probeTimeout time.Duration) (domain.Service, bool) {
	if probeTimeout <= 0 {
		return service, false
	}
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	if _, err := conn.Write(smbNegotiatePacket()); err != nil {
		return service, false
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 72 || resp[4] != 0xfe || resp[5] != 'S' || resp[6] != 'M' || resp[7] != 'B' {
		return service, false // not SMB2 (closed/reset/garbage/SMB1-only)
	}
	service.Name = "microsoft-ds"
	service.Product = "Windows"

	// Best-effort OS/build string: send a bare NTLM NEGOTIATE (no SPNEGO
	// wrapper — Windows' SMB server accepts this directly) asking for the
	// Version field, and read whatever the server sends back. Any failure
	// here still leaves the service correctly identified as SMB above.
	if _, err := conn.Write(smbSessionSetupPacket()); err != nil {
		return service, true
	}
	n, err = conn.Read(resp)
	if err != nil || n < 72 || resp[4] != 0xfe {
		return service, true
	}
	if version, ok := parseSessionSetupChallengeVersion(resp[:n]); ok {
		service.Version = version
	}
	return service, true
}

// smbNegotiatePacket builds a minimal SMB2 NEGOTIATE request offering the
// standard SMB2/SMB3 dialects. Byte-for-byte the same request
// internal/engine/js/smb.go's smbNegotiate sends — duplicated here rather
// than shared because that package pulls in goja/go-smb2 for its JS-exposed
// client, weight this read-only discovery probe has no reason to carry.
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

// ntlmVersionFlag is NTLMSSP_NEGOTIATE_VERSION ([MS-NLMP] 2.2.2.5) — asking
// the server to populate the Version field in both messages.
const ntlmVersionFlag = 0x02000000

// ntlmNegotiateMessage builds a minimal, fixed-length 40-byte NTLM Type 1
// (NEGOTIATE) message ([MS-NLMP] 2.2.1.1): the 32-byte fixed header (no
// domain/workstation names) plus the 8-byte Version field that is always
// present in the wire structure. Flags = UNICODE | REQUEST_TARGET | NTLM |
// EXTENDED_SESSIONSECURITY | VERSION | 128 | 56 — enough for a real Windows
// server to accept the message and echo its own Version in the CHALLENGE.
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

// smbSessionSetupPacket builds an SMB2 SESSION_SETUP request carrying a bare
// NTLM NEGOTIATE message (no SPNEGO/GSS-API wrapper) as its security buffer.
// Real Windows SMB servers accept an unwrapped NTLMSSP token here even
// though [MS-SMB2] formally specifies a GSS-API blob — this is the same
// shortcut several OS-fingerprinting tools use specifically to avoid
// building ASN.1 DER by hand for a probe that never intends to complete
// authentication.
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
	pkt[off+3] = 1                                     // SecurityMode: signing enabled
	secOff := 64 + fixedBody                           // relative to the start of the SMB2 header
	binary.LittleEndian.PutUint16(pkt[off+12:off+14], uint16(secOff))
	binary.LittleEndian.PutUint16(pkt[off+14:off+16], uint16(len(ntlm)))
	copy(pkt[4+64+fixedBody:], ntlm)
	return pkt
}

// parseSessionSetupChallengeVersion reads an SMB2 SESSION_SETUP response
// packet (NetBIOS header + 64-byte SMB2 header included, as returned by a
// raw conn.Read) and extracts the Windows build string from the NTLM
// CHALLENGE message's Version field ([MS-NLMP] 2.2.1.2 / 2.2.2.10), when the
// server included one. Works regardless of the response's NTSTATUS (usually
// STATUS_MORE_PROCESSING_REQUIRED, since no valid credential follows) — only
// the security buffer's content matters here.
func parseSessionSetupChallengeVersion(resp []byte) (string, bool) {
	const bodyOff = 68
	if len(resp) < bodyOff+8 {
		return "", false
	}
	secBufOffset := int(binary.LittleEndian.Uint16(resp[bodyOff+4 : bodyOff+6]))
	secBufLen := int(binary.LittleEndian.Uint16(resp[bodyOff+6 : bodyOff+8]))
	start := 4 + secBufOffset
	end := start + secBufLen
	if secBufOffset <= 0 || secBufLen <= 0 || start < 0 || end > len(resp) || start >= end {
		return "", false
	}
	return parseNTLMChallengeVersion(resp[start:end])
}

func parseNTLMChallengeVersion(buf []byte) (string, bool) {
	if len(buf) < 56 {
		return "", false
	}
	if string(buf[0:8]) != "NTLMSSP\x00" {
		return "", false
	}
	if binary.LittleEndian.Uint32(buf[8:12]) != 2 { // MessageType == CHALLENGE
		return "", false
	}
	flags := binary.LittleEndian.Uint32(buf[20:24])
	if flags&ntlmVersionFlag == 0 {
		return "", false
	}
	major, minor := buf[48], buf[49]
	build := binary.LittleEndian.Uint16(buf[50:52])
	return windowsBuildName(major, minor, build), true
}

// windowsBuildName maps an NTLM-reported NT version/build to a human string,
// the same job nmap's service/OS probes do from their own fingerprint
// database. Builds are shared between a desktop and server SKU released in
// the same wave (e.g. 7601 is both Windows 7 SP1 and Server 2008 R2), so an
// unresolvable ambiguity is named explicitly rather than guessed away.
func windowsBuildName(major, minor byte, build uint16) string {
	known := map[uint16]string{
		2600:  "Windows XP",
		3790:  "Windows Server 2003 / XP x64",
		6000:  "Windows Vista / Server 2008",
		6001:  "Windows Vista SP1 / Server 2008",
		6002:  "Windows Vista SP2 / Server 2008 SP2",
		7600:  "Windows 7 / Server 2008 R2",
		7601:  "Windows 7 SP1 / Server 2008 R2",
		9200:  "Windows 8 / Server 2012",
		9600:  "Windows 8.1 / Server 2012 R2",
		10240: "Windows 10 1507",
		10586: "Windows 10 1511",
		14393: "Windows 10 1607 / Server 2016",
		15063: "Windows 10 1703",
		16299: "Windows 10 1709",
		17134: "Windows 10 1803",
		17763: "Windows 10 1809 / Server 2019",
		18362: "Windows 10 1903",
		18363: "Windows 10 1909",
		19041: "Windows 10 2004",
		19042: "Windows 10 20H2",
		19043: "Windows 10 21H1",
		19044: "Windows 10 21H2",
		19045: "Windows 10 22H2",
		20348: "Windows Server 2022",
		22000: "Windows 11 21H2",
		22621: "Windows 11 22H2",
		22631: "Windows 11 23H2",
		26100: "Windows 11 24H2 / Server 2025",
	}
	if name, ok := known[build]; ok {
		return fmt.Sprintf("%s (build %d)", name, build)
	}
	return fmt.Sprintf("Windows NT %d.%d (build %d)", major, minor, build)
}
