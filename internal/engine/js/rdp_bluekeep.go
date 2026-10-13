// RDP capability data adapted from Rapid7's Metasploit Framework.
// Copyright (c) 2006-2026, Rapid7, Inc. See docs/licenses/METASPLOIT_RDP.txt.
package js

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CheckBlueKeep implements the check-only MS_T120 channel test described by
// Rapid7's auxiliary/scanner/rdp/cve_2019_0708_bluekeep (Scan action), using
// MS-RDPBCGR transport, GCC, standard security and session activation.
// No exploit, oversized channel data, credentials or Crash action is sent.
// Only the server's MCS Disconnect Provider Ultimatum after the channel probe
// is a positive match. NLA and protocol/transport failures remain explicit.
func CheckBlueKeep(ctx context.Context, host string, port int, timeout time.Duration) (bool, error) {
	w, protocol, close, err := openRDPWire(ctx, host, port, timeout, 1)
	if errors.Is(err, errRDPStandardRequired) {
		w, protocol, close, err = openRDPWire(ctx, host, port, timeout, 0)
	}
	if err != nil {
		return false, err
	}
	defer close()
	s := blueKeepSession{wire: w, channel: 1003}
	if err = w.send(blueKeepConnectInitial(protocol)); err != nil {
		return false, err
	}
	response, err := w.mcsFrame(0x7f)
	if err != nil {
		return false, fmt.Errorf("BlueKeep GCC: %w", err)
	}
	security, channels, err := blueKeepServerData(response, protocol == 0)
	if err != nil {
		return false, err
	}
	if len(channels) != 5 {
		return false, fmt.Errorf("BlueKeep: server did not bind the requested channel set")
	}
	if err = w.send(rdpTPDU([]byte{4, 1, 0, 1, 0})); err != nil {
		return false, err
	}
	if err = w.send(rdpTPDU([]byte{0x28})); err != nil {
		return false, err
	}
	attach, err := w.mcsFrame(0x2e)
	if err != nil {
		return false, err
	}
	if len(attach) != 11 || attach[8] != 0 {
		return false, fmt.Errorf("BlueKeep: invalid user confirm")
	}
	s.user = binary.BigEndian.Uint16(attach[9:])
	if s.user > 64534 {
		return false, fmt.Errorf("BlueKeep: invalid user ID")
	}
	for _, channel := range append([]uint16{s.user + 1001, s.channel}, channels...) {
		if err = w.send(rdpJoinRequest(s.user, channel)); err != nil {
			return false, err
		}
		join, err := w.mcsFrame(0x3e)
		if err != nil {
			return false, err
		}
		if len(join) < 13 || join[8] != 0 || binary.BigEndian.Uint16(join[9:]) != s.user || binary.BigEndian.Uint16(join[11:]) != channel {
			return false, fmt.Errorf("BlueKeep: channel %d join rejected or malformed", channel)
		}
	}
	if protocol == 0 {
		if err = s.standardSecurity(security); err != nil {
			return false, err
		}
	}
	if err = s.sendData(blueKeepClientInfo(), s.channel, 0x40); err != nil {
		return false, err
	}
	// Do not probe until the server has accepted licensing/session setup.
	var share uint32
	for i := 0; i < 32 && share == 0; i++ {
		p, err := w.frame()
		if err != nil {
			return false, fmt.Errorf("BlueKeep activation: %w", err)
		}
		data, flags, err := s.serverData(p)
		if err != nil {
			return false, err
		}
		if flags&0x80 != 0 && len(data) >= 4 && data[0] == 1 {
			if err = s.sendData(blueKeepLicenseRequest(), s.channel, 0x80); err != nil {
				return false, err
			}
			continue
		}
		if len(data) >= 10 && binary.LittleEndian.Uint16(data[2:])&15 == 1 {
			share = binary.LittleEndian.Uint32(data[6:])
		}
	}
	if share == 0 {
		return false, fmt.Errorf("BlueKeep: no Demand Active PDU")
	}
	confirm := blueKeepConfirmActive(share, s.user+1001)
	if err = s.sendData(confirm, s.channel, 0); err != nil {
		return false, err
	}
	sync := make([]byte, 4)
	binary.LittleEndian.PutUint16(sync, 1)
	binary.LittleEndian.PutUint16(sync[2:], s.user+1001)
	for _, p := range [][]byte{
		blueKeepShareData(share, s.user+1001, 0x1f, sync),
		blueKeepShareData(share, s.user+1001, 0x14, []byte{4, 0, 0, 0, 0, 0, 0, 0}),
		blueKeepShareData(share, s.user+1001, 0x14, []byte{1, 0, 0, 0, 0, 0, 0, 0}),
		blueKeepShareData(share, s.user+1001, 0x1c, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
		blueKeepShareData(share, s.user+1001, 0x27, []byte{0, 0, 0, 0, 3, 0, 50, 0}),
	} {
		if err = s.sendData(p, s.channel, 0); err != nil {
			return false, err
		}
	}
	ready := false
	for i := 0; i < 32; i++ {
		p, err := w.frame()
		if err != nil {
			return false, fmt.Errorf("BlueKeep session: %w", err)
		}
		data, _, err := s.serverData(p)
		if err != nil {
			return false, err
		}
		if len(data) >= 18 && binary.LittleEndian.Uint16(data[2:])&15 == 7 && data[14] == 0x28 {
			ready = true
			break
		}
	}
	if !ready {
		return false, fmt.Errorf("BlueKeep: RDP session was not activated")
	}
	for attempt := 0; attempt < 3; attempt++ {
		for _, size := range []int{16, 32} {
			data := make([]byte, 8+size)
			binary.LittleEndian.PutUint32(data, uint32(size))
			binary.LittleEndian.PutUint32(data[4:], 3) // FIRST | LAST
			binary.LittleEndian.PutUint32(data[8+size/4:], 2)
			if err = s.sendData(data, channels[1], 0); err != nil {
				return false, err
			}
		}
		deadline := time.Now().Add(time.Second)
		if end, ok := w.ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		_ = w.SetReadDeadline(deadline)
		for i := 0; i < 32; i++ {
			p, err := w.frame()
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() && w.ctx.Err() == nil {
					break
				}
				return false, fmt.Errorf("BlueKeep channel probe: %w", err)
			}
			if bytes.Equal(p, []byte{3, 0, 0, 9, 2, 0xf0, 0x80, 0x21, 0x80}) {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("BlueKeep: activated session, but no conclusive MS_T120 response")
}

type blueKeepSecurity struct {
	method          uint32
	random, modulus []byte
	exponent        uint32
}
type blueKeepSession struct {
	wire          *rdpWire
	user, channel uint16
	enc, dec      *rc4.Cipher
	mac           []byte
}

func blueKeepServerData(p []byte, standard bool) (blueKeepSecurity, []uint16, error) {
	var security blueKeepSecurity
	var channels []uint16
	seenSecurity := false
	start := -1
	for i := 9; i+4 <= len(p); i++ {
		if binary.LittleEndian.Uint16(p[i:]) == 0x0c01 {
			n := int(binary.LittleEndian.Uint16(p[i+2:]))
			if n >= 8 && i+n <= len(p) {
				start = i
				break
			}
		}
	}
	if start < 0 {
		return security, nil, fmt.Errorf("BlueKeep: missing GCC server data")
	}
	for i := start; i+4 <= len(p); {
		typ, n := binary.LittleEndian.Uint16(p[i:]), int(binary.LittleEndian.Uint16(p[i+2:]))
		if n < 4 || i+n > len(p) {
			return security, nil, fmt.Errorf("BlueKeep: truncated GCC server block")
		}
		b := p[i : i+n]
		switch typ {
		case 0x0c02:
			if seenSecurity {
				return security, nil, fmt.Errorf("BlueKeep: duplicate GCC security block")
			}
			seenSecurity = true
			if len(b) < 12 {
				return security, nil, fmt.Errorf("BlueKeep: truncated security block")
			}
			security.method = binary.LittleEndian.Uint32(b[4:])
			if standard && security.method != 0 {
				if len(b) < 20 {
					return security, nil, fmt.Errorf("BlueKeep: missing server random/certificate")
				}
				rn, cn := int(binary.LittleEndian.Uint32(b[12:])), int(binary.LittleEndian.Uint32(b[16:]))
				if rn != 32 || cn < 44 || cn > len(b)-20-rn {
					return security, nil, fmt.Errorf("BlueKeep: invalid server certificate length")
				}
				security.random = append([]byte(nil), b[20:20+rn]...)
				cert := b[20+rn : 20+rn+cn]
				if binary.LittleEndian.Uint32(cert)&0x7fffffff != 1 || string(cert[16:20]) != "RSA1" {
					return security, nil, fmt.Errorf("BlueKeep: unsupported standard-security certificate")
				}
				keylen := int(binary.LittleEndian.Uint32(cert[20:])) - 8
				if keylen < 64 || keylen > 512 || 36+keylen > len(cert) {
					return security, nil, fmt.Errorf("BlueKeep: invalid RSA key length")
				}
				security.exponent = binary.LittleEndian.Uint32(cert[32:])
				security.modulus = append([]byte(nil), cert[36:36+keylen]...)
			}
		case 0x0c03:
			if len(b) < 8 || binary.LittleEndian.Uint16(b[4:]) != 1003 {
				return security, nil, fmt.Errorf("BlueKeep: invalid MCS global channel")
			}
			count := int(binary.LittleEndian.Uint16(b[6:]))
			if count != 5 || 8+count*2 > len(b) {
				return security, nil, fmt.Errorf("BlueKeep: unexpected static channel count")
			}
			for j := 0; j < count; j++ {
				channels = append(channels, binary.LittleEndian.Uint16(b[8+j*2:]))
			}
		}
		i += n
	}
	if standard && !seenSecurity {
		return security, nil, fmt.Errorf("BlueKeep: missing GCC security block")
	}
	if standard && security.method != 0 && len(security.modulus) == 0 {
		return security, nil, fmt.Errorf("BlueKeep: missing standard-security key")
	}
	return security, channels, nil
}

func (s *blueKeepSession) standardSecurity(sec blueKeepSecurity) error {
	if sec.method == 0 {
		return nil
	}
	if sec.method != 1 && sec.method != 2 && sec.method != 8 {
		return fmt.Errorf("BlueKeep: unsupported encryption method %d", sec.method)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	n := littleBigInt(sec.modulus)
	if sec.exponent < 3 || n.Sign() <= 0 {
		return fmt.Errorf("BlueKeep: invalid RSA public key")
	}
	cipher := new(big.Int).Exp(littleBigInt(random), new(big.Int).SetUint64(uint64(sec.exponent)), n).Bytes()
	encrypted := make([]byte, len(sec.modulus)+8)
	for i := range cipher {
		encrypted[i] = cipher[len(cipher)-1-i]
	}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint16(data, 1)
	binary.LittleEndian.PutUint32(data[4:], uint32(len(encrypted)))
	if err := s.sendData(append(data, encrypted...), s.channel, 0); err != nil {
		return err
	}
	enc, dec, mac := blueKeepKeys(random, sec.random)
	if sec.method != 2 {
		enc, dec, mac = append([]byte(nil), enc[:8]...), append([]byte(nil), dec[:8]...), append([]byte(nil), mac[:8]...)
		if sec.method == 1 {
			copy(enc, []byte{0xd1, 0x26, 0x9e})
			copy(dec, []byte{0xd1, 0x26, 0x9e})
			copy(mac, []byte{0xd1, 0x26, 0x9e})
		} else {
			enc[0], dec[0], mac[0] = 0xd1, 0xd1, 0xd1
		}
	}
	s.enc, _ = rc4.NewCipher(enc)
	s.dec, _ = rc4.NewCipher(dec)
	s.mac = mac
	return nil
}

func littleBigInt(b []byte) *big.Int {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(out)
}

func blueKeepKeys(client, server []byte) (enc, dec, mac []byte) {
	salted := func(secret []byte, first byte) []byte {
		var out []byte
		for i := 0; i < 3; i++ {
			h := sha1.New()
			h.Write(bytes.Repeat([]byte{first + byte(i)}, i+1))
			h.Write(secret)
			h.Write(client)
			h.Write(server)
			m := md5.New()
			m.Write(secret)
			m.Write(h.Sum(nil))
			out = append(out, m.Sum(nil)...)
		}
		return out
	}
	premaster := append(append([]byte(nil), client[:24]...), server[:24]...)
	master := salted(premaster, 'A')
	session := salted(master, 'X')
	final := func(key []byte) []byte {
		h := md5.New()
		h.Write(key)
		h.Write(client)
		h.Write(server)
		return h.Sum(nil)
	}
	return final(session[32:48]), final(session[16:32]), session[:16]
}

func blueKeepMAC(key, data []byte) []byte {
	h := sha1.New()
	h.Write(key)
	h.Write(bytes.Repeat([]byte{0x36}, 40))
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(data)))
	h.Write(length)
	h.Write(data)
	m := md5.New()
	m.Write(key)
	m.Write(bytes.Repeat([]byte{0x5c}, 48))
	m.Write(h.Sum(nil))
	return m.Sum(nil)[:8]
}

func (s *blueKeepSession) sendData(data []byte, channel, flags uint16) error {
	var payload []byte
	if s.enc != nil {
		flags |= 8
	}
	if flags != 0 {
		payload = make([]byte, 4)
		binary.LittleEndian.PutUint16(payload, flags)
	}
	if s.enc != nil {
		payload = append(payload, blueKeepMAC(s.mac, data)...)
		encrypted := make([]byte, len(data))
		s.enc.XORKeyStream(encrypted, data)
		payload = append(payload, encrypted...)
	} else {
		payload = append(payload, data...)
	}
	b := make([]byte, 8)
	b[0] = 0x64
	binary.BigEndian.PutUint16(b[1:], s.user)
	binary.BigEndian.PutUint16(b[3:], channel)
	b[5] = 0x70
	binary.BigEndian.PutUint16(b[6:], uint16(len(payload))|0x8000)
	return s.wire.send(rdpTPDU(append(b, payload...)))
}

func (s *blueKeepSession) serverData(p []byte) ([]byte, uint16, error) {
	if len(p) < 15 || p[0] != 3 || p[7] != 0x68 {
		return nil, 0, nil
	}
	i := 14
	length := int(p[13])
	if p[13]&0x80 != 0 {
		length = int(p[13]&0x7f)<<8 | int(p[14])
		i = 15
	}
	if length > len(p)-i {
		return nil, 0, fmt.Errorf("BlueKeep: truncated MCS data")
	}
	data := p[i : i+length]
	var flags uint16
	// With TLS the normal Share Control PDU starts with totalLength, which
	// can have the same bits as SEC_LICENSE_PKT/SEC_ENCRYPT. Licensing alone
	// still carries a Basic Security Header (flagsHi is zero); a normal Share
	// Control Header has pduType in that position. Never interpret its length
	// as encryption flags.
	licenseHeader := len(data) >= 4 && binary.LittleEndian.Uint16(data)&0x80 != 0 && binary.LittleEndian.Uint16(data[2:]) == 0
	if len(data) >= 4 && (s.dec != nil || licenseHeader) {
		flags = binary.LittleEndian.Uint16(data)
		data = data[4:]
		if flags&8 != 0 {
			if s.dec == nil || len(data) < 8 {
				return nil, 0, fmt.Errorf("BlueKeep: invalid encrypted server data")
			}
			mac := data[:8]
			plain := make([]byte, len(data)-8)
			s.dec.XORKeyStream(plain, data[8:])
			if !bytes.Equal(mac, blueKeepMAC(s.mac, plain)) {
				return nil, 0, fmt.Errorf("BlueKeep: invalid RDP message signature")
			}
			data = plain
		}
	}
	return data, flags, nil
}

func blueKeepBlock(kind uint16, data []byte) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b, kind)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(data)+4))
	return append(b, data...)
}
func blueKeepPER(data []byte) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(data))|0x8000)
	return append(b, data...)
}
func blueKeepBER(tag byte, data []byte) []byte {
	b := []byte{tag, 0x82, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(len(data)))
	return append(b, data...)
}

func blueKeepConnectInitial(protocol uint32) []byte {
	return rdpConnectInitial(protocol, []string{"cliprdr", "MS_T120", "rdpsnd", "snddbg", "rdpdr"}, 2)
}

func rdpConnectInitial(protocol uint32, names []string, maxUsers uint32) []byte {
	core := make([]byte, 212)
	binary.LittleEndian.PutUint32(core, 0x80004)
	binary.LittleEndian.PutUint16(core[4:], 800)
	binary.LittleEndian.PutUint16(core[6:], 600)
	binary.LittleEndian.PutUint16(core[8:], 0xca01)
	binary.LittleEndian.PutUint16(core[10:], 0xaa03)
	binary.LittleEndian.PutUint32(core[12:], 1033)
	binary.LittleEndian.PutUint32(core[16:], 2600)
	for i, c := range []byte("wscan") {
		core[20+i*2] = c
	}
	binary.LittleEndian.PutUint32(core[52:], 4)
	binary.LittleEndian.PutUint32(core[60:], 12)
	binary.LittleEndian.PutUint16(core[128:], 0xca01)
	binary.LittleEndian.PutUint16(core[130:], 1)
	binary.LittleEndian.PutUint16(core[136:], 24)
	binary.LittleEndian.PutUint16(core[138:], 7)
	binary.LittleEndian.PutUint16(core[140:], 1)
	binary.LittleEndian.PutUint32(core[208:], protocol)
	cluster := make([]byte, 8)
	binary.LittleEndian.PutUint32(cluster, 9)
	security := make([]byte, 8)
	binary.LittleEndian.PutUint32(security, 3)
	channels := make([]byte, 4+len(names)*12)
	binary.LittleEndian.PutUint32(channels, uint32(len(names)))
	for i, c := range names {
		copy(channels[4+i*12:], c)
		flag := uint32(0xc0000000)
		if i == 0 {
			flag = 0xc0a00000
		}
		if i == 1 {
			flag = 0x80800000
		}
		binary.LittleEndian.PutUint32(channels[4+i*12+8:], flag)
	}
	blocks := blueKeepBlock(0xc001, core)
	blocks = append(blocks, blueKeepBlock(0xc004, cluster)...)
	blocks = append(blocks, blueKeepBlock(0xc002, security)...)
	blocks = append(blocks, blueKeepBlock(0xc003, channels)...)
	gcc := append([]byte{0, 8, 0, 16, 0, 1, 0xc0, 0, 'D', 'u', 'c', 'a'}, blueKeepPER(blocks)...)
	gcc = append([]byte{0, 5, 0, 20, 124, 0, 1}, blueKeepPER(gcc)...)
	params := func(values ...uint32) []byte {
		var data []byte
		for _, v := range values {
			b := new(big.Int).SetUint64(uint64(v)).Bytes()
			if len(b) == 0 {
				b = []byte{0}
			}
			if b[0]&0x80 != 0 {
				b = append([]byte{0}, b...)
			}
			data = append(data, 2, byte(len(b)))
			data = append(data, b...)
		}
		return append([]byte{0x30, byte(len(data))}, data...)
	}
	body := []byte{4, 1, 1, 4, 1, 1, 1, 1, 0xff}
	body = append(body, params(34, maxUsers, 0, 1, 0, 1, 65535, 2)...)
	body = append(body, params(1, 1, 1, 1, 0, 1, 1056, 2)...)
	body = append(body, params(65535, 64535, 65535, 1, 0, 1, 65535, 2)...)
	body = append(body, blueKeepBER(4, gcc)...)
	packet := blueKeepBER(0x65, body)
	packet = append([]byte{0x7f}, packet...)
	return rdpTPDU(packet)
}

func blueKeepClientInfo() []byte {
	b := make([]byte, 18+10)
	binary.LittleEndian.PutUint32(b[4:], 0x133)
	address := []byte{'0', 0, '.', 0, '0', 0, '.', 0, '0', 0, '.', 0, '0', 0, 0, 0}
	b = append(b, 2, 0, byte(len(address)), 0)
	b = append(b, address...)
	var directory []byte
	for _, c := range []byte(`C:\Windows\System32\mstscax.dll`) {
		directory = append(directory, c, 0)
	}
	directory = append(directory, 0, 0)
	b = append(b, byte(len(directory)), 0)
	b = append(b, directory...)
	b = append(b, make([]byte, 172)...)
	b = append(b, 0, 0, 0, 0, 0x27, 0, 0, 0, 0, 0)
	return b
}

func blueKeepLicenseRequest() []byte {
	b := []byte{0x13, 3, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}
	b = append(b, make([]byte, 32)...)
	b = append(b, 2, 0, 64, 0)
	b = append(b, make([]byte, 64)...)
	for _, v := range []uint16{0x0f, 0x10} {
		b = append(b, byte(v), 0, 6, 0, 'w', 's', 'c', 'a', 'n', 0)
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func blueKeepShareControl(typ, source uint16, data []byte) []byte {
	b := make([]byte, 6)
	binary.LittleEndian.PutUint16(b, uint16(6+len(data)))
	binary.LittleEndian.PutUint16(b[2:], typ)
	binary.LittleEndian.PutUint16(b[4:], source)
	return append(b, data...)
}
func blueKeepShareData(share uint32, source uint16, typ byte, data []byte) []byte {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b, share)
	b[5] = 1
	binary.LittleEndian.PutUint16(b[6:], uint16(4+len(data)))
	b[8] = typ
	return blueKeepShareControl(0x17, source, append(b, data...))
}

func blueKeepConfirmActive(share uint32, source uint16) []byte {
	// Standard capability sets from MS-RDPBCGR; the handshake shape follows
	// Rapid7's BSD-licensed RDP scanner. Share/user IDs come from the server.
	b, _ := hex.DecodeString("ea030100ea0306008e014d53545343000e00000001001800010003000002000000000d04000000000000000002001c00100001000100010020035802000001000100000001000000030058000000000000000000000000000000000000000000010014000000010047012a000101010100000000010101010001010000000000010101000001010100000000a1060000000000000084030000000000e40400001300280000000003780000007800000050010000000000000000000000000000000000000000000008000a000100140014000a0008000600000007000c00000000000000000005000c00000000000200020009000800000000000f000800010000000d005800010000000904000004000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000800010000000e0008000100000010003400fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000fe000001400000080001000102000000")
	binary.LittleEndian.PutUint32(b, share)
	return blueKeepShareControl(0x13, source, b)
}
