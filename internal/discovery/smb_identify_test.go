package discovery

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"wscan/internal/domain"
)

// fakeChallengeMessage hand-builds an NTLM CHALLENGE (Type 2) message with a
// Version field, mirroring [MS-NLMP] 2.2.1.2 byte-for-byte so
// parseNTLMChallengeVersion is tested against real wire layout rather than a
// round-trip of our own encoder.
func fakeChallengeMessage(major, minor byte, build uint16) []byte {
	buf := make([]byte, 56)
	copy(buf[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(buf[8:12], 2) // MessageType = CHALLENGE
	binary.LittleEndian.PutUint32(buf[20:24], ntlmVersionFlag)
	buf[48] = major
	buf[49] = minor
	binary.LittleEndian.PutUint16(buf[50:52], build)
	return buf
}

func TestParseNTLMChallengeVersionWindows7SP1(t *testing.T) {
	version, ok := parseNTLMChallengeVersion(fakeChallengeMessage(6, 1, 7601))
	if !ok {
		t.Fatal("expected a version to be found")
	}
	if version != "Windows 7 SP1 / Server 2008 R2 (build 7601)" {
		t.Fatalf("unexpected version string: %q", version)
	}
}

func TestParseNTLMChallengeVersionUnknownBuild(t *testing.T) {
	version, ok := parseNTLMChallengeVersion(fakeChallengeMessage(10, 0, 12345))
	if !ok {
		t.Fatal("expected a version to be found even for an unmapped build")
	}
	if version != "Windows NT 10.0 (build 12345)" {
		t.Fatalf("unexpected fallback version string: %q", version)
	}
}

func TestParseNTLMChallengeVersionMissingFlagReturnsFalse(t *testing.T) {
	buf := fakeChallengeMessage(6, 1, 7601)
	binary.LittleEndian.PutUint32(buf[20:24], 0) // no NTLMSSP_NEGOTIATE_VERSION
	if _, ok := parseNTLMChallengeVersion(buf); ok {
		t.Fatal("must not report a version when the server never set the VERSION flag")
	}
}

func TestParseNTLMChallengeVersionTooShort(t *testing.T) {
	if _, ok := parseNTLMChallengeVersion(make([]byte, 10)); ok {
		t.Fatal("must not panic or succeed on a truncated buffer")
	}
}

// fakeSMB2SessionSetupResponse wraps a security buffer (an NTLM CHALLENGE, in
// the real flow) into a minimal SMB2 SESSION_SETUP response packet, so
// parseSessionSetupChallengeVersion is exercised against the same NetBIOS +
// SMB2-header + body framing identifySMB actually reads off the wire.
func fakeSMB2SessionSetupResponse(securityBuffer []byte) []byte {
	const bodyOff = 68
	pkt := make([]byte, bodyOff+8+len(securityBuffer))
	copy(pkt[4:8], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(pkt[bodyOff+4:bodyOff+6], uint16(bodyOff+8-4)) // SecurityBufferOffset, relative to header start
	binary.LittleEndian.PutUint16(pkt[bodyOff+6:bodyOff+8], uint16(len(securityBuffer)))
	copy(pkt[bodyOff+8:], securityBuffer)
	return pkt
}

func TestParseSessionSetupChallengeVersionEndToEnd(t *testing.T) {
	resp := fakeSMB2SessionSetupResponse(fakeChallengeMessage(6, 2, 9200))
	version, ok := parseSessionSetupChallengeVersion(resp)
	if !ok {
		t.Fatal("expected to find a version in a well-formed response")
	}
	if version != "Windows 8 / Server 2012 (build 9200)" {
		t.Fatalf("unexpected version: %q", version)
	}
}

// TestIdentifySMBEndToEnd runs identifySMB against a tiny fake listener that
// replays canned SMB2 NEGOTIATE + SESSION_SETUP responses, proving the probe
// correctly drives both round trips over a real net.Conn (not just the pure
// parsing functions above).
func TestIdentifySMBEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// NEGOTIATE request in, a minimal valid-looking SMB2 NEGOTIATE
		// response out.
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		negResp := make([]byte, 72)
		copy(negResp[4:8], []byte{0xfe, 'S', 'M', 'B'})
		if _, err := conn.Write(negResp); err != nil {
			return
		}

		// SESSION_SETUP request in, a canned CHALLENGE-bearing response out.
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write(fakeSMB2SessionSetupResponse(fakeChallengeMessage(6, 1, 7601)))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	service, ok := identifySMB(conn, domain.Service{Host: "127.0.0.1", Port: 4445}, time.Second)
	if !ok {
		t.Fatal("expected identifySMB to recognize the fake SMB2 server")
	}
	if service.Name != "microsoft-ds" {
		t.Fatalf("Name = %q, want microsoft-ds", service.Name)
	}
	if service.Version != "Windows 7 SP1 / Server 2008 R2 (build 7601)" {
		t.Fatalf("Version = %q", service.Version)
	}
}

func TestIdentifySMBReturnsFalseAgainstNonSMBServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("220 not-an-smb-server ready\r\n"))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, ok := identifySMB(conn, domain.Service{Host: "127.0.0.1", Port: 21}, time.Second)
	if ok {
		t.Fatal("must not report SMB against a plain-text banner server")
	}
}

// TestSMBProbeTimeoutRespectsContextDeadline pins smbProbeTimeout's
// ctx-bounded cap, the mechanism that keeps identifySMB from ever running
// past a scan's own ambient deadline.
func TestSMBProbeTimeoutRespectsContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if got := smbProbeTimeout(ctx); got > 200*time.Millisecond {
		t.Fatalf("smbProbeTimeout = %v, want <= 200ms given the context deadline", got)
	}

	if got := smbProbeTimeout(context.Background()); got != 900*time.Millisecond {
		t.Fatalf("smbProbeTimeout with no deadline = %v, want the 900ms default budget", got)
	}
}
