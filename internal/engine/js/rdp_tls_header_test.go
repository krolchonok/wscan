package js

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBlueKeepTLSShareLengthDoesNotBecomeSecurityFlags(t *testing.T) {
	s := blueKeepSession{}
	for _, size := range []int{0x80, 0x88, 0x188, 0x280} {
		data := make([]byte, size)
		binary.LittleEndian.PutUint16(data, uint16(size))
		binary.LittleEndian.PutUint16(data[2:], 0x11)
		binary.LittleEndian.PutUint32(data[6:], 0x12345678)
		got, flags, err := s.serverData(rdpTestServerData(data))
		if err != nil || flags != 0 || !bytes.Equal(got, data) {
			t.Fatalf("Share PDU length=%d misclassified: flags=%d err=%v", size, flags, err)
		}
	}
	license := []byte{0x80, 0, 0, 0, 0xff, 3, 16, 0, 7, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0}
	got, flags, err := s.serverData(rdpTestServerData(license))
	if err != nil || flags != 0x80 || !bytes.Equal(got, license[4:]) {
		t.Fatal("real license security header no longer recognized")
	}
}
