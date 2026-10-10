package js

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrSMB1Unsupported means the server rejected every dialect we offered
// (DialectIndex 0xFFFF) — i.e. SMB1 itself isn't available, so the target
// cannot be vulnerable to an SMB1-specific bug like MS17-010 regardless of
// patch level.
var ErrSMB1Unsupported = errors.New("server does not support SMB1 (no vulnerable dialect to check)")

// CheckMS17010 detects CVE-2017-0143/MS17-010 ("EternalBlue") the same way
// nmap's own library/nmap/scripts/smb-vuln-ms17-010.nse does (that script and
// its library/nmap/nselib/smb.lua + smbauth.lua dependencies are vendored in
// this repo and were read byte-for-byte to build this): negotiate a plain,
// non-extended-security SMB1 session, log on with a null/anonymous session
// (empty username, the single 0-byte LM response get_password_response uses
// for hash_type "none", empty NTLM response), tree-connect to IPC$, then send
// a single, deliberately malformed SMB_COM_TRANSACTION request (a
// PeekNamedPipe call on an invalid FID, with parameter/data offsets and a
// declared word count that intentionally don't match the real payload size —
// copied byte-for-byte from the reference script, not "cleaned up", since
// those exact malformed values are what the bug depends on). The response's
// NTSTATUS alone reveals patch status:
//
//	STATUS_INSUFF_SERVER_RESOURCES (0xC0000205) -> unpatched (vulnerable)
//	STATUS_ACCESS_DENIED           (0xC0000022) -> patched
//	STATUS_INVALID_HANDLE          (0xC0000008) -> patched
//
// nmap categorizes this exact check "safe" (unlike MS08-067's NetprPathCompare
// probe) — it never triggers the actual overflow, only observes which error
// path an unpatched kernel takes before it would. No state-changing SMB
// operation (no write, no file created) happens at any point.
func CheckMS17010(parent context.Context, host string, port int, timeout time.Duration) (bool, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", joinAddr(host, port))
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	const (
		cmdNegotiate   = 0x72
		cmdSessionSetup = 0x73
		cmdTreeConnect  = 0x75
		cmdTransaction  = 0x25
	)
	// flags2: 32BIT_STATUS | IS_LONG_NAME | KNOWS_LONG_NAMES | SECURITY_SIGNATURE.
	// Deliberately NOT setting EXTENDED_SECURITY (0x0800): without it in our
	// own request, a compliant server won't require NTLMSSP/SPNEGO either, so
	// the classic (and much simpler) "basic" SESSION_SETUP_ANDX null-session
	// path below applies — exactly what disable_extended() does in smb.lua.
	const flags2 = 0x4000 | 0x0040 | 0x0001 | 0x0004
	const pid = 1
	const mid = 1 // smb.lua never increments smb['mid'] across these calls either.

	sessionKey, err := smb1Negotiate(conn, flags2, pid, mid)
	if errors.Is(err, ErrSMB1Unsupported) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("SMB1 negotiate: %w", err)
	}
	uid, err := smb1SessionSetupAnonymous(conn, flags2, pid, mid, sessionKey)
	if err != nil {
		return false, fmt.Errorf("SMB1 session setup: %w", err)
	}
	tid, err := smb1TreeConnectIPC(conn, flags2, pid, mid, uid, host)
	if err != nil {
		return false, fmt.Errorf("SMB1 tree connect: %w", err)
	}
	status, err := smb1PeekNamedPipeProbe(conn, flags2, pid, mid, uid, tid)
	if err != nil {
		return false, fmt.Errorf("SMB1 transaction probe: %w", err)
	}

	switch status {
	case 0xc0000205: // STATUS_INSUFF_SERVER_RESOURCES
		return true, nil
	case 0xc0000022, 0xc0000008: // STATUS_ACCESS_DENIED / STATUS_INVALID_HANDLE
		return false, nil
	default:
		return false, fmt.Errorf("inconclusive (not vulnerable, not confirmed patched): unexpected status 0x%08x", status)
	}
}

// smb1Header builds the 32-byte SMB1 (CIFS) header, field-for-field matching
// smb.lua's smb_encode_header (status/pid_high/signature/reserved are always
// zero for a request; message signing is a no-op for this whole flow since
// the null/anonymous session never derives a MAC key — see smbauth.lua's
// get_password_response hash_type=="none" case).
func smb1Header(command byte, flags2 uint16, tid, pid, uid, mid uint16) []byte {
	h := make([]byte, 32)
	h[0], h[1], h[2], h[3] = 0xFF, 'S', 'M', 'B'
	h[4] = command
	h[9] = 0x18 // flags: SMB_FLAGS_CANONICAL_PATHNAMES | SMB_FLAGS_CASELESS_PATHNAMES
	binary.LittleEndian.PutUint16(h[10:12], flags2)
	binary.LittleEndian.PutUint16(h[24:26], tid)
	binary.LittleEndian.PutUint16(h[26:28], pid)
	binary.LittleEndian.PutUint16(h[28:30], uid)
	binary.LittleEndian.PutUint16(h[30:32], mid)
	return h
}

// smb1Send frames one SMB1 request exactly as smb.lua's smb_send does: a
// 1-byte word count, the parameter words, a 2-byte byte count, then the data
// bytes, all behind a 4-byte big-endian NetBIOS session length. wordCount is
// taken as an explicit argument (rather than always derived from
// len(params)/2) because the final exploit probe below must declare a word
// count that does not match the actual parameter bytes it sends — the same
// deliberate mismatch the reference script sends.
func smb1Send(conn net.Conn, header []byte, params []byte, wordCount int, data []byte) error {
	body := make([]byte, 0, len(header)+1+len(params)+2+len(data))
	body = append(body, header...)
	body = append(body, byte(wordCount))
	body = append(body, params...)
	bcc := make([]byte, 2)
	binary.LittleEndian.PutUint16(bcc, uint16(len(data)))
	body = append(body, bcc...)
	body = append(body, data...)

	framed := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(framed[0:4], uint32(len(body)))
	copy(framed[4:], body)
	_, err := conn.Write(framed)
	return err
}

// smb1Response is one parsed SMB1 reply: the 32-byte header plus the
// separated parameter/data sections (mirrors smb.lua's smb_read).
type smb1Response struct {
	header []byte
	params []byte
	data   []byte
}

func (r smb1Response) command() byte  { return r.header[4] }
func (r smb1Response) status() uint32 { return binary.LittleEndian.Uint32(r.header[5:9]) }
func (r smb1Response) uid() uint16    { return binary.LittleEndian.Uint16(r.header[28:30]) }
func (r smb1Response) tid() uint16    { return binary.LittleEndian.Uint16(r.header[24:26]) }

func smb1Read(conn net.Conn) (smb1Response, error) {
	var lenBuf [4]byte
	if _, err := readFullSMB1(conn, lenBuf[:]); err != nil {
		return smb1Response{}, fmt.Errorf("read netbios header: %w", err)
	}
	netbiosLen := binary.BigEndian.Uint32(lenBuf[:]) & 0x00FFFFFF
	if netbiosLen < 32+1+2 {
		return smb1Response{}, fmt.Errorf("short SMB1 response (%d bytes)", netbiosLen)
	}
	body := make([]byte, netbiosLen)
	if _, err := readFullSMB1(conn, body); err != nil {
		return smb1Response{}, fmt.Errorf("read SMB1 body: %w", err)
	}
	if body[0] != 0xFF || body[1] != 'S' || body[2] != 'M' || body[3] != 'B' {
		return smb1Response{}, fmt.Errorf("not an SMB1 response (got %x)", body[0:4])
	}
	header := body[0:32]
	pos := 32
	wordCount := int(body[pos])
	pos++
	paramsLen := wordCount * 2
	if pos+paramsLen+2 > len(body) {
		return smb1Response{}, fmt.Errorf("truncated SMB1 parameters")
	}
	params := body[pos : pos+paramsLen]
	pos += paramsLen
	byteCount := int(binary.LittleEndian.Uint16(body[pos : pos+2]))
	pos += 2
	var data []byte
	if pos+byteCount <= len(body) {
		data = body[pos : pos+byteCount]
	}
	return smb1Response{header: header, params: params, data: data}, nil
}

func readFullSMB1(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// smb1Negotiate sends SMB_COM_NEGOTIATE offering only the "NT LM 0.12"
// dialect (plus the trailing empty dialect smb.lua's negotiate_v1 also
// sends) and returns the server's SessionKey, the one field the following
// anonymous SESSION_SETUP_ANDX needs to echo back.
func smb1Negotiate(conn net.Conn, flags2 uint16, pid, mid uint16) (uint32, error) {
	header := smb1Header(0x72, flags2, 0, pid, 0, mid)
	data := []byte{0x02}
	data = append(data, []byte("NT LM 0.12\x00")...)
	data = append(data, 0x02, 0x00)
	if err := smb1Send(conn, header, nil, 0, data); err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}
	resp, err := smb1Read(conn)
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	if resp.status() != 0 {
		return 0, fmt.Errorf("server rejected negotiate: status 0x%08x", resp.status())
	}
	if len(resp.params) < 2 {
		return 0, fmt.Errorf("negotiate response carried no dialect index")
	}
	// Per [MS-CIFS]: if none of the client's offered dialects are supported,
	// the server sets DialectIndex to 0xFFFF and the response carries no
	// further parameter fields at all (that's the whole body) — the normal,
	// expected reply from an SMB2/3-only (SMB1-disabled) server, which by
	// definition can't be vulnerable to an SMB1 bug. ErrSMB1Unsupported lets
	// the caller report a clean "not vulnerable", not a parse error.
	if dialect := binary.LittleEndian.Uint16(resp.params[0:2]); dialect != 0 {
		return 0, ErrSMB1Unsupported
	}
	// parameters: DialectIndex(I2) SecurityMode(B) MaxMpx(I2) MaxVc(I2)
	// MaxBuffer(I4) MaxRawBuffer(I4) SessionKey(I4) ...
	const sessionKeyOffset = 2 + 1 + 2 + 2 + 4 + 4
	if len(resp.params) < sessionKeyOffset+4 {
		return 0, fmt.Errorf("negotiate response too short for a session key")
	}
	return binary.LittleEndian.Uint32(resp.params[sessionKeyOffset : sessionKeyOffset+4]), nil
}

// smb1SessionSetupAnonymous performs the non-extended-security
// SMB_COM_SESSION_SETUP_ANDX null-session logon (empty username/domain, the
// single 0-byte LM response and empty NTLM response smbauth.lua's
// get_password_response returns for the anonymous account) and returns the
// UID the server assigned.
func smb1SessionSetupAnonymous(conn net.Conn, flags2 uint16, pid, mid uint16, sessionKey uint32) (uint16, error) {
	header := smb1Header(0x73, flags2, 0, pid, 0, mid)
	lm := []byte{0x00}
	ntlm := []byte{}
	params := make([]byte, 0, 26)
	params = append(params, 0xFF, 0x00)
	params = append(params, le16(0)...)                  // ANDXOffset
	params = append(params, le16(0xFFFF)...)              // MaxBufferSize
	params = append(params, le16(1)...)                   // MaxMpxCount
	params = append(params, le16(1)...)                   // VcNumber
	params = append(params, le32(sessionKey)...)          // SessionKey
	params = append(params, le16(uint16(len(lm)))...)     // OEMPasswordLen
	params = append(params, le16(uint16(len(ntlm)))...)   // UnicodePasswordLen
	params = append(params, le32(0)...)                   // Reserved
	params = append(params, le32(0x00000050)...)          // Capabilities
	data := make([]byte, 0, len(lm)+len(ntlm)+24)
	data = append(data, lm...)
	data = append(data, ntlm...)
	data = append(data, 0x00)                  // AccountName = ""
	data = append(data, 0x00)                  // PrimaryDomain = ""
	data = append(data, []byte("Nmap\x00")...) // NativeOS (cosmetic)
	data = append(data, []byte("Native Lanman\x00")...)

	if err := smb1Send(conn, header, params, len(params)/2, data); err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}
	resp, err := smb1Read(conn)
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	if resp.status() != 0 {
		return 0, fmt.Errorf("anonymous logon rejected: status 0x%08x", resp.status())
	}
	return resp.uid(), nil
}

// smb1TreeConnectIPC connects to \\<host>\IPC$ (SMB_COM_TREE_CONNECT_ANDX)
// and returns the TID needed for the probe below.
func smb1TreeConnectIPC(conn net.Conn, flags2 uint16, pid, mid, uid uint16, host string) (uint16, error) {
	header := smb1Header(0x75, flags2, 0, pid, uid, mid)
	params := make([]byte, 0, 8)
	params = append(params, 0xFF, 0x00)
	params = append(params, le16(0)...) // ANDXOffset
	params = append(params, le16(0)...) // Flags
	params = append(params, le16(0)...) // PasswordLength (share-level security, unused)
	path := `\\` + host + `\IPC$`
	data := make([]byte, 0, len(path)+1+6)
	data = append(data, []byte(path)...)
	data = append(data, 0x00)
	data = append(data, []byte("?????\x00")...)

	if err := smb1Send(conn, header, params, len(params)/2, data); err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}
	resp, err := smb1Read(conn)
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	if resp.status() != 0 {
		return 0, fmt.Errorf("tree connect to IPC$ rejected: status 0x%08x", resp.status())
	}
	if resp.tid() == 0 {
		return 0, fmt.Errorf("server did not establish a tree connection")
	}
	return resp.tid(), nil
}

// smb1PeekNamedPipeProbe sends the actual MS17-010 detection packet: an
// SMB_COM_TRANSACTION carrying a PeekNamedPipe (0x0023) subcommand targeting
// "\PIPE\" with intentionally malformed Parameter/DataOffset fields (encoded
// big-endian from pre-swapped literals, and a declared word count of 16 that
// doesn't match the 20 actual parameter words sent) — copied field-for-field
// from library/nmap/scripts/smb-vuln-ms17-010.nse's check_ms17010(), which is
// itself the canonical, widely-used public PoC for this bug. Returns the raw
// NTSTATUS from the response for the caller to classify.
func smb1PeekNamedPipeProbe(conn net.Conn, flags2 uint16, pid, mid, uid, tid uint16) (uint32, error) {
	header := smb1Header(0x25, flags2, tid, pid, uid, mid)
	params := make([]byte, 0, 40)
	params = append(params, be16(0x0000)...) // Total Parameter count
	params = append(params, be16(0x0000)...) // Total Data count
	params = append(params, be16(0xFFFF)...) // Max Parameter count
	params = append(params, be16(0xFFFF)...) // Max Data count
	params = append(params, 0x00, 0x00)      // Max setup count, Reserved
	params = append(params, be16(0x0000)...) // Flags
	params = append(params, be32(0x00000000)...) // Timeout
	params = append(params, be16(0x0000)...)      // Reserved
	params = append(params, be16(0x0000)...)      // ParameterCount
	params = append(params, be16(0x4a00)...)      // ParameterOffset (malformed, deliberate)
	params = append(params, be16(0x0000)...)      // DataCount
	params = append(params, be16(0x4a00)...)      // DataOffset (malformed, deliberate)
	params = append(params, 0x02, 0x00)           // SetupCount, Reserved
	params = append(params, be16(0x2300)...)      // Setup[0]: PeekNamedPipe opcode
	params = append(params, be16(0x0000)...)      // Setup[1]
	params = append(params, be16(0x0700)...)      // BCC: length of "\PIPE\"
	params = append(params, be16(0x5c50)...)      // "\P"
	params = append(params, be16(0x4950)...)      // "IP"
	params = append(params, be16(0x455c)...)      // "E\"

	if err := smb1Send(conn, header, params, 0x10, nil); err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}
	resp, err := smb1Read(conn)
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	if resp.command() != 0x25 {
		return 0, fmt.Errorf("unexpected response command 0x%02x", resp.command())
	}
	return resp.status(), nil
}

func le16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
