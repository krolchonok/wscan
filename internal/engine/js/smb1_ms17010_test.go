package js

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestCheckMS17010FailsCleanlyAgainstUnreachableHost mirrors
// TestCheckZerologonFailsCleanlyAgainstUnreachableHost/
// TestCheckMS08067FailsCleanlyAgainstUnreachableHost: a full
// vulnerable/patched run needs a real (or lab) SMB1 target — this only pins
// that a dial failure never gets reported as "vulnerable".
func TestCheckMS17010FailsCleanlyAgainstUnreachableHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	vulnerable, err := CheckMS17010(ctx, "127.0.0.1", 4445, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error dialing an unreachable SMB1 endpoint")
	}
	if vulnerable {
		t.Fatal("must never report vulnerable on a dial/negotiate failure")
	}
}

// TestCheckMS17010ReturnsCleanErrorAgainstNonSMBServer exercises the full
// framing path (not just the dial step) against a server that answers but
// isn't SMB1 at all, proving a garbage/non-SMB response is rejected rather
// than misread as some NTSTATUS value.
func TestCheckMS17010ReturnsCleanErrorAgainstNonSMBServer(t *testing.T) {
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
		_, _ = conn.Write([]byte("220 not-smb ready\r\n"))
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	vulnerable, err := CheckMS17010(ctx, host, port, time.Second)
	if err == nil {
		t.Fatal("expected an error against a non-SMB1 server")
	}
	if vulnerable {
		t.Fatal("must never report vulnerable against garbage input")
	}
}

// writeFakeSMB1Response builds and writes one canned SMB1 response frame
// (NetBIOS length + 32-byte header + word-count-prefixed params +
// byte-count-prefixed data), the exact wire shape smb1Read expects.
func writeFakeSMB1Response(conn net.Conn, command byte, status uint32, tid, uid uint16, params []byte) {
	header := make([]byte, 32)
	header[0], header[1], header[2], header[3] = 0xFF, 'S', 'M', 'B'
	header[4] = command
	binary.LittleEndian.PutUint32(header[5:9], status)
	binary.LittleEndian.PutUint16(header[24:26], tid)
	binary.LittleEndian.PutUint16(header[28:30], uid)

	body := append([]byte{}, header...)
	body = append(body, byte(len(params)/2))
	body = append(body, params...)
	body = append(body, 0x00, 0x00) // byte count = 0, no data

	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(body)))
	copy(frame[4:], body)
	_, _ = conn.Write(frame)
}

// runFakeMS17010Server replays the four canned responses (negotiate, session
// setup, tree connect, transaction) a successful CheckMS17010 run needs,
// proving the request/response framing round trips end to end without a
// real Windows target. finalStatus is the NTSTATUS the canned
// SMB_COM_TRANSACTION response carries.
func runFakeMS17010Server(t *testing.T, finalStatus uint32) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)

		if _, err := conn.Read(buf); err != nil {
			return
		}
		negParams := make([]byte, 20) // dialect(2)+secmode(1)+maxmpx(2)+maxvc(2)+maxbuf(4)+maxraw(4)+sessionkey(4), padded to an even word count
		binary.LittleEndian.PutUint32(negParams[15:19], 0x11223344)
		writeFakeSMB1Response(conn, 0x72, 0, 0, 0, negParams)

		if _, err := conn.Read(buf); err != nil {
			return
		}
		writeFakeSMB1Response(conn, 0x73, 0, 0, 7, make([]byte, 6))

		if _, err := conn.Read(buf); err != nil {
			return
		}
		writeFakeSMB1Response(conn, 0x75, 0, 9, 7, make([]byte, 6))

		if _, err := conn.Read(buf); err != nil {
			return
		}
		writeFakeSMB1Response(conn, 0x25, finalStatus, 9, 7, nil)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func TestCheckMS17010VulnerableStatus(t *testing.T) {
	host, port := runFakeMS17010Server(t, 0xc0000205) // STATUS_INSUFF_SERVER_RESOURCES
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	vulnerable, err := CheckMS17010(ctx, host, port, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !vulnerable {
		t.Fatal("expected vulnerable=true for a canned STATUS_INSUFF_SERVER_RESOURCES response")
	}
}

func TestCheckMS17010PatchedStatus(t *testing.T) {
	host, port := runFakeMS17010Server(t, 0xc0000022) // STATUS_ACCESS_DENIED
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	vulnerable, err := CheckMS17010(ctx, host, port, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vulnerable {
		t.Fatal("expected vulnerable=false for a canned STATUS_ACCESS_DENIED response")
	}
}

func TestCheckMS17010InconclusiveStatus(t *testing.T) {
	host, port := runFakeMS17010Server(t, 0xc0000001) // arbitrary, unmapped status
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	vulnerable, err := CheckMS17010(ctx, host, port, time.Second)
	if err == nil {
		t.Fatal("expected an error for an unmapped status code")
	}
	if vulnerable {
		t.Fatal("must never report vulnerable for an unmapped status code")
	}
}
