package js

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
)

// smbNullInitiator performs NTLM anonymous authentication, rather than silently
// replacing an empty username with guest. The fork already used by go-msrpc
// exposes its Initiator interface; upstream go-smb2 rejects empty usernames.
// MS-NLMP 3.3.2: empty NT response, a single zero byte LM response.
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
// No password-derived key exists for this mode. Servers requiring signing,
// encryption or authenticated RPC may reject it; no guest fallback is attempted.
type smbNullInitiator struct{}

func (*smbNullInitiator) OID() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
}

const smbNullFlags uint32 = 0x00088205

func (*smbNullInitiator) InitSecContext() ([]byte, error) {
	packet := make([]byte, 32)
	copy(packet, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(packet[8:12], 1)
	binary.LittleEndian.PutUint32(packet[12:16], smbNullFlags)
	return packet, nil
}
func (*smbNullInitiator) AcceptSecContext(challenge []byte) ([]byte, error) {
	if len(challenge) < 48 || string(challenge[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(challenge[8:12]) != 2 {
		return nil, fmt.Errorf("SMB null: некорректный NTLM challenge")
	}
	flags := binary.LittleEndian.Uint32(challenge[20:24]) & smbNullFlags
	packet := make([]byte, 65)
	copy(packet, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(packet[8:12], 3)
	binary.LittleEndian.PutUint16(packet[12:14], 1)
	binary.LittleEndian.PutUint16(packet[14:16], 1)
	binary.LittleEndian.PutUint32(packet[16:20], 64)
	// NT response length, max length and offset deliberately remain zero.
	for _, at := range []int{28, 36, 44, 52} {
		binary.LittleEndian.PutUint32(packet[at+4:at+8], 64)
	}
	binary.LittleEndian.PutUint32(packet[60:64], flags|0x00000800)
	return packet, nil
}
func (*smbNullInitiator) Sum([]byte) []byte  { return nil }
func (*smbNullInitiator) SessionKey() []byte { return make([]byte, 16) }
