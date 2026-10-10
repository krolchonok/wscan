package js

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/hirochachacha/go-smb2"
)

// smbModule exposes SMBClient as a goja constructor so both call styles seen
// in real nuclei-templates work: `new m.SMBClient()` and `m.SMBClient()`
// (upstream templates use both — see library/nuclei-templates/javascript/
// enumeration/smb/*.yaml). A plain `FunctionCall`-shaped factory only
// supports the second form; goja refuses `new` on it ("Value is not a
// constructor").
func smbModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	obj := vm.NewObject()
	ctor := func(call goja.ConstructorCall) *goja.Object {
		c := &SMBClient{ctx: ctx, timeout: timeout}
		inst := vm.NewObject()
		_ = inst.Set("ConnectSMBInfoMode", func(call goja.FunctionCall) goja.Value {
			host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			info, err := c.ConnectSMBInfoMode(host, port)
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			return vm.ToValue(info)
		})
		_ = inst.Set("ListSMBv2Metadata", func(call goja.FunctionCall) goja.Value {
			args := make([]any, len(call.Arguments))
			for i, a := range call.Arguments {
				args[i] = a.Export()
			}
			info, err := c.ListSMBv2Metadata(args...)
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			return vm.ToValue(info)
		})
		_ = inst.Set("ListShares", func(call goja.FunctionCall) goja.Value {
			host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			user, pass := "", ""
			if len(call.Arguments) > 2 {
				user = fmt.Sprint(call.Argument(2).Export())
			}
			if len(call.Arguments) > 3 {
				pass = fmt.Sprint(call.Argument(3).Export())
			}
			shares, err := c.ListShares(host, port, user, pass)
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			return vm.ToValue(shares)
		})
		_ = inst.Set("ListSharesWithAccess", func(call goja.FunctionCall) goja.Value {
			host, port, err := asHostPort(call.Argument(0).Export(), call.Argument(1).Export())
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			user, pass := "", ""
			if len(call.Arguments) > 2 {
				user = fmt.Sprint(call.Argument(2).Export())
			}
			if len(call.Arguments) > 3 {
				pass = fmt.Sprint(call.Argument(3).Export())
			}
			shares, err := c.ListSharesReadOnly(host, port, strings.TrimSpace(user), strings.TrimSpace(pass))
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			return vm.ToValue(shares)
		})
		_ = inst.Set("ListSharesReadOnly", inst.Get("ListSharesWithAccess"))
		return inst
	}
	_ = obj.Set("SMBClient", ctor)
	return obj
}

// SMBClient mirrors nuclei/smb.SMBClient (subset used by our library).
type SMBClient struct {
	ctx     context.Context
	timeout time.Duration
}

// SMBLog is ConnectSMBInfoMode's return shape, matching field-for-field
// (not just in spirit) github.com/zmap/zgrab2/lib/smb/smb.SMBLog — the real
// struct nuclei's own ConnectSMBInfoMode returns. Every
// nuclei-templates/javascript/enumeration/smb/*.yaml template accesses the
// exact Go field names below (e.g. response.Version.VerString,
// response.NegotiationLog.SystemTime), not a json-tag alias, which is why
// the json tags here are kept identical to the field names — our runtime's
// goja.TagFieldNameMapper("json", false) uses them as the JS property name.
//
// NativeOs/NTLM/GroupName are always empty: the real zgrab2 client fills
// them from an SMB1 plaintext session-setup exchange we don't perform yet.
// Templates that treat an empty value as a valid "not applicable" case
// (e.g. samba-detect.yaml) still work; one that requires a non-empty NTLM
// (ntlm-info.yaml) will run cleanly but find nothing until that's added.
type SMBLog struct {
	SupportV1      bool             `json:"SupportV1"`
	Version        *SMBVersion      `json:"Version,omitempty"`
	NativeOs       string           `json:"NativeOs"`
	NTLM           string           `json:"NTLM"`
	GroupName      string           `json:"GroupName"`
	Capabilities   *SMBCapabilities `json:"Capabilities,omitempty"`
	HasNTLM        bool             `json:"HasNTLM"`
	NegotiationLog *NegotiationLog  `json:"NegotiationLog,omitempty"`
}

// SMBVersion mirrors zgrab2's SMBVersions.
type SMBVersion struct {
	Major     uint8  `json:"Major"`
	Minor     uint8  `json:"Minor"`
	Revision  uint8  `json:"Revision"`
	VerString string `json:"VerString"`
}

// SMBCapabilities mirrors zgrab2's SMBCapabilities (decoded from the
// NEGOTIATE response's Capabilities bitmask, [MS-SMB2] §2.2.4).
type SMBCapabilities struct {
	DFSSupport bool `json:"DFSSupport"`
	Leasing    bool `json:"Leasing"`
	LargeMTU   bool `json:"LargeMTU"`
	MultiChan  bool `json:"MultiChan"`
	Persist    bool `json:"Persist"`
	DirLeasing bool `json:"DirLeasing"`
	Encryption bool `json:"Encryption"`
}

// NegotiationLog mirrors the subset of zgrab2's NegotiationLog our raw
// NEGOTIATE probe can fill without a full session setup.
type NegotiationLog struct {
	SecurityMode    uint16 `json:"SecurityMode"`
	DialectRevision uint16 `json:"DialectRevision"`
	// SystemTime / ServerStartTime are Unix seconds (converted from the wire
	// FILETIME, matching zgrab2's getTime()) — 0 when the response was too
	// short to carry them. Templates multiply by 1000 for JS Date().
	SystemTime      uint32 `json:"SystemTime"`
	ServerStartTime uint32 `json:"ServerStartTime"`
}

// ServiceSMB is ListSMBv2Metadata's return shape, matching
// github.com/praetorian-inc/fingerprintx's pkg/plugins.ServiceSMB — a
// different upstream library than ConnectSMBInfoMode's zgrab2 SMBLog, with
// a different field set (nuclei itself backs the two methods differently).
//
// SigningEnabled/SigningRequired are real, decoded from the same NEGOTIATE
// response's SecurityMode bits. OSVersion/NetBIOS*/DNS*/ForestName are
// always empty: the real fingerprintx plugin reads them from the SMB2
// NTLMSSP CHALLENGE message's Version field and TargetInfo AV_PAIRs, which
// needs a SPNEGO-wrapped SESSION_SETUP exchange we don't perform yet.
// Templates requiring those non-empty (smb-enum-domains.yaml, smb-enum.yaml,
// smb-os-detect.yaml) run cleanly but won't match until that's added.
type ServiceSMB struct {
	SigningEnabled      bool   `json:"SigningEnabled"`
	SigningRequired     bool   `json:"SigningRequired"`
	OSVersion           string `json:"OSVersion"`
	NetBIOSComputerName string `json:"NetBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"NetBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"DNSComputerName,omitempty"`
	DNSDomainName       string `json:"DNSDomainName,omitempty"`
	ForestName          string `json:"ForestName,omitempty"`
}

// NewSMBClient constructs an SMBClient for direct use outside the goja
// runtime — see ssh.go's NewSSHClient.
func NewSMBClient(ctx context.Context, timeout time.Duration) *SMBClient {
	return &SMBClient{ctx: ctx, timeout: timeout}
}

// Login performs only the SMB session-setup (authentication) and immediately
// logs off — the pure "does this credential work" check the credential-spray
// engine needs. Unlike ListShares, it does not also enumerate share names, a
// second request that can fail for unrelated policy reasons (e.g. IPC$
// access restricted) even when the credential itself is valid.
func (c *SMBClient) Login(host string, port int, user, pass string) (bool, error) {
	session, conn, err := c.session(host, port, user, pass)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	defer session.Logoff()
	return true, nil
}

func (c *SMBClient) ConnectSMBInfoMode(host string, port int) (*SMBLog, error) {
	return smbNegotiate(c.ctx, host, port, c.timeout)
}

func (c *SMBClient) ListSMBv2Metadata(args ...any) (*ServiceSMB, error) {
	host, port, _, _, err := smbArgs(args)
	if err != nil {
		return nil, err
	}
	log, err := smbNegotiate(c.ctx, host, port, c.timeout)
	if err != nil {
		return nil, err
	}
	svc := &ServiceSMB{}
	if log.NegotiationLog != nil {
		mode := log.NegotiationLog.SecurityMode
		svc.SigningEnabled = mode&0x1 != 0
		svc.SigningRequired = mode&0x2 != 0
	}
	return svc, nil
}

func (c *SMBClient) ListShares(host string, port int, user, pass string) ([]string, error) {
	session, conn, err := c.session(host, port, user, pass)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer session.Logoff()
	names, err := session.ListSharenames()
	if err != nil {
		return nil, err
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}

// ShareAccess is one share's name plus the effective READ/WRITE access the
// credential used to list it actually has — the same two columns nxc's own
// `smb --shares` module reports, rather than just a bare name (which says
// nothing about whether the share is actually usable).
type ShareAccess struct {
	Name  string `json:"Name"`
	Read  bool   `json:"Read"`
	Write bool   `json:"Write"`
}

// ListSharesWithAccess is ListShares plus a per-share READ/WRITE probe: READ
// is "can list the share's root directory", WRITE is "can create (and then
// immediately remove) a uniquely-named directory at the share's root" — the
// same create-then-delete technique nxc/CrackMapExec use, left with nothing
// behind on success. IPC$ (not a filesystem share) simply reports
// Read=Write=false when the mount/probe fails, same as any other share a
// credential genuinely cannot access.
func (c *SMBClient) ListSharesWithAccess(host string, port int, user, pass string) ([]ShareAccess, error) {
	session, conn, err := c.session(host, port, user, pass)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer session.Logoff()
	return sharesWithAccess(session)
}

// ListSharesWithAccessUsingHash is ListSharesWithAccess's pass-the-hash
// counterpart, mirroring ListSharesWithHash.
func (c *SMBClient) ListSharesWithAccessUsingHash(host string, port int, domainName, user, hash string) ([]ShareAccess, error) {
	initiator, err := hashInitiator(domainName, user, hash)
	if err != nil {
		return nil, err
	}
	session, conn, err := c.dial(host, port, initiator)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer session.Logoff()
	return sharesWithAccess(session)
}

func sharesWithAccess(session *smb2.Session) ([]ShareAccess, error) {
	names, err := session.ListSharenames()
	if err != nil {
		return nil, err
	}
	out := make([]ShareAccess, 0, len(names))
	for _, name := range names {
		access := ShareAccess{Name: name}
		// IPC$ is the named-pipe RPC endpoint, not a filesystem — ReadDir/
		// Mkdir against it always fail with a protocol-level error (not
		// "access denied"), which would misreport a real lack-of-access as
		// a probe failure. nxc's own output treats it the same way (blank
		// permissions), so skip the filesystem probe for it entirely.
		if strings.EqualFold(name, "IPC$") {
			out = append(out, access)
			continue
		}
		if share, err := session.Mount(name); err == nil {
			if _, err := share.ReadDir("."); err == nil {
				access.Read = true
			}
			probe := fmt.Sprintf("wscan-probe-%d", time.Now().UnixNano())
			if share.Mkdir(probe, 0) == nil {
				access.Write = true
				_ = share.Remove(probe)
			}
			_ = share.Umount()
		}
		out = append(out, access)
	}
	return out, nil
}

// LoginWithHash performs the SMB session-setup using an NTLM hash instead of
// a plaintext password (pass-the-hash) — backs domain.Credential{Type:
// "ntlm-hash"} in the credential-spray engine.
func (c *SMBClient) LoginWithHash(host string, port int, domainName, user, hash string) (bool, error) {
	initiator, err := hashInitiator(domainName, user, hash)
	if err != nil {
		return false, err
	}
	session, conn, err := c.dial(host, port, initiator)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	defer session.Logoff()
	return true, nil
}

// ListSharesWithHash is ListShares' pass-the-hash counterpart — same
// Credential.Type == "ntlm-hash" support LoginWithHash gives the pure login
// check, for the post-auth "smb-shares" enumeration module.
func (c *SMBClient) ListSharesWithHash(host string, port int, domainName, user, hash string) ([]string, error) {
	initiator, err := hashInitiator(domainName, user, hash)
	if err != nil {
		return nil, err
	}
	session, conn, err := c.dial(host, port, initiator)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	defer session.Logoff()
	names, err := session.ListSharenames()
	if err != nil {
		return nil, err
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}

func hashInitiator(domainName, user, hash string) (*smb2.NTLMInitiator, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("invalid NTLM hash: %w", err)
	}
	return &smb2.NTLMInitiator{User: user, Hash: hashBytes, Domain: domainName}, nil
}

func (c *SMBClient) session(host string, port int, user, pass string) (*smb2.Session, net.Conn, error) {
	return c.dial(host, port, &smb2.NTLMInitiator{User: user, Password: pass})
}

func (c *SMBClient) dial(host string, port int, initiator smb2.Initiator) (*smb2.Session, net.Conn, error) {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(c.ctx, "tcp", joinAddr(host, port))
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	stop := context.AfterFunc(c.ctx, func() { _ = conn.Close() })
	defer stop()
	dialer := &smb2.Dialer{Initiator: initiator}
	session, err := dialer.Dial(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return session, conn, nil
}

func smbArgs(args []any) (host string, port int, user, pass string, err error) {
	if len(args) < 2 {
		return "", 0, "", "", fmt.Errorf("ListSMBv2Metadata requires host, port")
	}
	host, port, err = asHostPort(args[0], args[1])
	if err != nil {
		return "", 0, "", "", err
	}
	if len(args) >= 4 {
		user = fmt.Sprint(args[2])
		pass = fmt.Sprint(args[3])
	}
	return host, port, user, pass, nil
}

// filetimeToUnix converts a Windows FILETIME (100ns intervals since
// 1601-01-01) to Unix epoch seconds, matching zgrab2's getTime() exactly so
// NegotiationLog.SystemTime/ServerStartTime line up with what templates
// written against the real zgrab2 client expect.
func filetimeToUnix(ft uint64) uint32 {
	if ft == 0 {
		return 0
	}
	const epochOffsetSeconds = 11644473600
	return uint32(ft/1e7 - epochOffsetSeconds)
}

// smbNegotiate sends a minimal SMB2 NEGOTIATE and parses dialect/caps/time
// from the response, filling an SMBLog shaped like the real zgrab2 client's.
func smbNegotiate(ctx context.Context, host string, port int, timeout time.Duration) (*SMBLog, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", joinAddr(host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SMB2 NEGOTIATE with dialects 0x0202, 0x0210, 0x0300, 0x0311
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0311}
	bodyLen := 36 + len(dialects)*2
	pkt := make([]byte, 4+64+bodyLen) // NetBIOS + header + body
	// NetBIOS session message
	binary.BigEndian.PutUint32(pkt[0:4], uint32(64+bodyLen))
	// SMB2 header
	copy(pkt[4:8], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[8:10], 64)      // StructureSize
	binary.LittleEndian.PutUint16(pkt[16:18], 0)      // Command = NEGOTIATE
	binary.LittleEndian.PutUint32(pkt[28:32], 0)      // MessageID
	binary.LittleEndian.PutUint32(pkt[36:40], 0xFEFF) // ProcessID leftover noop
	// Body
	off := 68
	binary.LittleEndian.PutUint16(pkt[off:off+2], 36) // StructureSize
	binary.LittleEndian.PutUint16(pkt[off+2:off+4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(pkt[off+4:off+6], 1)  // SecurityMode signing enabled
	binary.LittleEndian.PutUint32(pkt[off+8:off+12], 0) // Capabilities
	// ClientGuid zeros at off+12
	binary.LittleEndian.PutUint32(pkt[off+28:off+32], 0) // NegotiateContextOffset
	binary.LittleEndian.PutUint16(pkt[off+32:off+34], 0)
	binary.LittleEndian.PutUint16(pkt[off+34:off+36], 0)
	for i, dalt := range dialects {
		binary.LittleEndian.PutUint16(pkt[off+36+i*2:off+36+i*2+2], dalt)
	}
	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 72 {
		return nil, fmt.Errorf("smb negotiate: short response")
	}
	if resp[4] != 0xfe || resp[5] != 'S' || resp[6] != 'M' || resp[7] != 'B' {
		// Maybe SMB1 — still counts as support.
		return &SMBLog{
			SupportV1: true,
			HasNTLM:   true,
			Version:   &SMBVersion{Major: 1, VerString: "SMB 1.0"},
		}, nil
	}

	// Body starts right after the 4-byte NetBIOS prefix + 64-byte SMB2
	// header, per [MS-SMB2] §2.2.4 NEGOTIATE Response layout:
	//   0 StructureSize(2) 2 SecurityMode(2) 4 DialectRevision(2)
	//   6 Reserved(2) 8 ServerGuid(16) 24 Capabilities(4)
	//   28 MaxTransactSize(4) 32 MaxReadSize(4) 36 MaxWriteSize(4)
	//   40 SystemTime(8) 48 ServerStartTime(8) 56 SecurityBufferOffset(2) ...
	const bodyOff = 68
	body := n - bodyOff
	if body < 6 {
		return nil, fmt.Errorf("smb negotiate: response too short for a NEGOTIATE body")
	}
	securityMode := binary.LittleEndian.Uint16(resp[bodyOff+2 : bodyOff+4])
	dialect := binary.LittleEndian.Uint16(resp[bodyOff+4 : bodyOff+6])

	ver := &SMBVersion{VerString: "SMB2"}
	switch dialect {
	case 0x0202:
		*ver = SMBVersion{Major: 2, Minor: 0, Revision: 2, VerString: "SMB 2.0.2"}
	case 0x0210:
		*ver = SMBVersion{Major: 2, Minor: 1, VerString: "SMB 2.1"}
	case 0x0300:
		*ver = SMBVersion{Major: 3, Minor: 0, VerString: "SMB 3.0"}
	case 0x0302:
		*ver = SMBVersion{Major: 3, Minor: 0, Revision: 2, VerString: "SMB 3.0.2"}
	case 0x0311:
		*ver = SMBVersion{Major: 3, Minor: 1, Revision: 1, VerString: "SMB 3.1.1"}
	}

	var capsField uint32
	if body >= 28 {
		capsField = binary.LittleEndian.Uint32(resp[bodyOff+24 : bodyOff+28])
	}
	caps := &SMBCapabilities{
		DFSSupport: capsField&0x00000001 != 0,
		Leasing:    capsField&0x00000002 != 0,
		LargeMTU:   capsField&0x00000004 != 0,
		MultiChan:  capsField&0x00000008 != 0,
		Persist:    capsField&0x00000010 != 0,
		DirLeasing: capsField&0x00000020 != 0,
		Encryption: capsField&0x00000040 != 0,
	}

	neg := &NegotiationLog{SecurityMode: securityMode, DialectRevision: dialect}
	if body >= 56 {
		systemTime := binary.LittleEndian.Uint64(resp[bodyOff+40 : bodyOff+48])
		serverStartTime := binary.LittleEndian.Uint64(resp[bodyOff+48 : bodyOff+56])
		neg.SystemTime = filetimeToUnix(systemTime)
		neg.ServerStartTime = filetimeToUnix(serverStartTime)
	}

	return &SMBLog{
		Version:        ver,
		Capabilities:   caps,
		HasNTLM:        true,
		NegotiationLog: neg,
	}, nil
}
