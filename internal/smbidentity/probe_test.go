package smbidentity

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func challengeFixture() []byte {
	utf := func(s string) []byte {
		b := make([]byte, len(s)*2)
		for i := range s {
			b[i*2] = s[i]
		}
		return b
	}
	target := utf("CLIENT2")
	var av bytes.Buffer
	for _, item := range []struct {
		id    uint16
		value string
	}{{1, "CLIENT2"}, {2, "LAB"}, {3, "client2.lab.local"}, {4, "lab.local"}} {
		v := utf(item.value)
		_ = binary.Write(&av, binary.LittleEndian, item.id)
		_ = binary.Write(&av, binary.LittleEndian, uint16(len(v)))
		av.Write(v)
	}
	av.Write(make([]byte, 4))
	b := make([]byte, 56)
	copy(b, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(b[8:12], 2)
	binary.LittleEndian.PutUint32(b[20:24], 0x02020001)
	binary.LittleEndian.PutUint16(b[12:14], uint16(len(target)))
	binary.LittleEndian.PutUint32(b[16:20], 56)
	binary.LittleEndian.PutUint16(b[40:42], uint16(av.Len()))
	binary.LittleEndian.PutUint32(b[44:48], uint32(56+len(target)))
	b[48] = 6
	b[49] = 1
	binary.LittleEndian.PutUint16(b[50:52], 7601)
	return append(append(b, target...), av.Bytes()...)
}
func TestIdentityChallengeAndMalformedOffsets(t *testing.T) {
	b := challengeFixture()
	r, err := Parse(b)
	if err != nil || r.ComputerName != "CLIENT2" || r.DomainName != "LAB" || r.DNSDomainName != "lab.local" || !r.TargetIsServer || r.TargetIsDomain || r.OSVersion != "6.1.7601" {
		t.Fatal(r, err)
	}
	for _, mutate := range []func([]byte){func(b []byte) { binary.LittleEndian.PutUint32(b[44:48], 0xffffffff) }, func(b []byte) { binary.LittleEndian.PutUint16(b[40:42], 65535) }, func(b []byte) { binary.LittleEndian.PutUint32(b[8:12], 3) }} {
		b := challengeFixture()
		mutate(b)
		if _, err := Parse(b); err == nil {
			t.Fatal("bad NTLM buffer accepted")
		}
	}
}
func TestIdentityProbeHandlesFragmentsAndNeverAuthenticates(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = readSMBFrame(c); err != nil {
			done <- err
			return
		}
		negotiation := make([]byte, 128)
		copy(negotiation[4:8], []byte{0xfe, 'S', 'M', 'B'})
		binary.BigEndian.PutUint32(negotiation[:4], 124)
		binary.LittleEndian.PutUint16(negotiation[70:72], 3)
		for i := 0; i < len(negotiation); i += 2 {
			if _, err = c.Write(negotiation[i : i+2]); err != nil {
				done <- err
				return
			}
		}
		req, err := readSMBFrame(c)
		if err != nil {
			done <- err
			return
		}
		i := bytes.Index(req, []byte("NTLMSSP\x00"))
		if i < 0 || binary.LittleEndian.Uint32(req[i+8:i+12]) != 1 {
			done <- io.ErrUnexpectedEOF
			return
		}
		token := challengeFixture()
		packet := make([]byte, 76+len(token))
		binary.BigEndian.PutUint32(packet[:4], uint32(len(packet)-4))
		copy(packet[4:8], []byte{0xfe, 'S', 'M', 'B'})
		binary.LittleEndian.PutUint16(packet[72:74], 72)
		binary.LittleEndian.PutUint16(packet[74:76], uint16(len(token)))
		copy(packet[76:], token)
		_, err = c.Write(packet)
		if err != nil {
			done <- err
			return
		}
		one := make([]byte, 1)
		n, err := c.Read(one)
		if n != 0 || err != io.EOF {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- nil
	}()
	r, err := Probe(context.Background(), "127.0.0.1", l.Addr().(*net.TCPAddr).Port, time.Second)
	if err != nil || r.ComputerName != "CLIENT2" || !r.SigningRequired {
		t.Fatal(r, err)
	}
	if err := <-done; err != nil {
		t.Fatal("unexpected extra authentication or bad frame", err)
	}
}
