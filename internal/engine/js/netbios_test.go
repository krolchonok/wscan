package js

import (
	"context"
	"net"
	"testing"
	"time"
)

// fakeNodeStatusResponse builds a synthetic RFC 1002 §4.2.18 NODE STATUS
// RESPONSE packet carrying exactly one unique <00> name — hand-built from
// the spec (not captured), the same approach used elsewhere in this engine
// for raw-byte protocols (e.g. SMBGhost's negotiate response in smb_test.go).
func fakeNodeStatusResponse(name string, suffix byte, group bool) []byte {
	b := make([]byte, 0, 90)
	b = append(b, 0x80, 0xf0)             // NAME_TRN_ID: echoes the query
	b = append(b, 0x84, 0x00)             // flags: response, authoritative
	b = append(b, 0x00, 0x00)             // QDCOUNT
	b = append(b, 0x00, 0x01)             // ANCOUNT
	b = append(b, 0x00, 0x00)             // NSCOUNT
	b = append(b, 0x00, 0x00)             // ARCOUNT
	b = append(b, nbstatQuery[12:46]...)  // RR_NAME: same encoded name as the query
	b = append(b, 0x00, 0x21)             // RR_TYPE = NBSTAT
	b = append(b, 0x00, 0x01)             // RR_CLASS = IN
	b = append(b, 0x00, 0x00, 0x00, 0x00) // TTL
	b = append(b, 0x00, 0x00)             // RDLENGTH (unused by the parser)
	b = append(b, 0x01)                   // NUM_NAMES = 1

	nameField := make([]byte, 15)
	copy(nameField, name)
	for i := len(name); i < 15; i++ {
		nameField[i] = ' '
	}
	b = append(b, nameField...)
	b = append(b, suffix)
	flags := uint16(0x0400) // ACT=1, everything else clear
	if group {
		flags |= 0x8000
	}
	b = append(b, byte(flags>>8), byte(flags))

	b = append(b, make([]byte, 12)...) // STATISTICS padding (unit id etc, unused)
	return b
}

func TestParseNBSTATResponseFindsUniqueWorkstationName(t *testing.T) {
	resp := fakeNodeStatusResponse("TESTPC", 0x00, false)
	name, err := parseNBSTATResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if name != "TESTPC" {
		t.Fatalf("name = %q, want TESTPC", name)
	}
}

func TestParseNBSTATResponseSkipsGroupAndWrongSuffix(t *testing.T) {
	// A group name at <00> must not match (it's the domain/workgroup name,
	// not the computer name), nor should a unique name at a different
	// suffix (<20> is the File Server Service, not Workstation).
	group := fakeNodeStatusResponse("WORKGROUP", 0x00, true)
	if _, err := parseNBSTATResponse(group); err == nil {
		t.Fatal("a group <00> name must not be returned as the workstation name")
	}
	wrongSuffix := fakeNodeStatusResponse("TESTPC", 0x20, false)
	if _, err := parseNBSTATResponse(wrongSuffix); err == nil {
		t.Fatal("a <20> (File Server Service) entry must not be returned for a <00> lookup")
	}
}

func TestParseNBSTATResponseTooShort(t *testing.T) {
	if _, err := parseNBSTATResponse([]byte{0x01, 0x02}); err == nil {
		t.Fatal("expected an error for a too-short response")
	}
}

func TestResolveNetBIOSNameEndToEnd(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)

	resp := fakeNodeStatusResponse("DC01", 0x00, false)
	go func() {
		buf := make([]byte, 2048)
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}
		_, _ = pc.WriteTo(resp, clientAddr)
	}()

	name, err := ResolveNetBIOSName(context.Background(), "127.0.0.1", addr.Port, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if name != "DC01" {
		t.Fatalf("name = %q, want DC01", name)
	}
}
