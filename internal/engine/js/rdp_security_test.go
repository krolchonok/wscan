package js

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestBlueKeepStandardSecurityKnownKeysAndMAC(t *testing.T) {
	client, server := make([]byte, 32), make([]byte, 32)
	for i := range client {
		client[i] = byte(i)
		server[i] = byte(i + 32)
	}
	enc, dec, mac := blueKeepKeys(client, server)
	// Independently computed MS-RDPBCGR salted SHA1/MD5 vectors.
	for got, want := range map[string]string{hex.EncodeToString(enc): "702783c08474414a33a259c6faed480c", hex.EncodeToString(dec): "1cb207f61b7cd10dca9ec78871d0a142", hex.EncodeToString(mac): "815370c6e31347c463ed25f1af48bbdf"} {
		if got != want {
			t.Fatalf("key %s, want %s", got, want)
		}
	}
	data, _ := hex.DecodeString("12001700ef03ea0302000001040024000000")
	if got := hex.EncodeToString(blueKeepMAC(mac, data)); got != "72e3b652f0feaab9" {
		t.Fatalf("signature %s", got)
	}
}

func TestBlueKeepStandardSecurityExchangeAndEncryptedMessages(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	modulus := make([]byte, 128)
	be := key.N.Bytes()
	for i := range be {
		modulus[i] = be[len(be)-1-i]
	}
	serverRandom := bytes.Repeat([]byte{0x27}, 32)
	for _, method := range []uint32{1, 2, 8} {
		h, p := rdpTestServer(t, func(w *rdpWire) error {
			packet, err := w.frame()
			if err != nil {
				return err
			}
			if len(packet) != 15+8+128+8 || binary.LittleEndian.Uint16(packet[15:]) != 1 {
				return fmt.Errorf("invalid security exchange")
			}
			cipher := littleBigInt(packet[23:151])
			random := new(big.Int).Exp(cipher, key.D, key.N).Bytes()
			clientRandom := make([]byte, 32)
			if len(random) > len(clientRandom) {
				return fmt.Errorf("invalid client random")
			}
			for i := range random {
				clientRandom[i] = random[len(random)-1-i]
			}
			enc, dec, mac := blueKeepKeys(clientRandom, serverRandom)
			if method != 2 {
				enc, dec, mac = enc[:8], dec[:8], mac[:8]
				if method == 1 {
					copy(enc, []byte{0xd1, 0x26, 0x9e})
					copy(dec, []byte{0xd1, 0x26, 0x9e})
					copy(mac, []byte{0xd1, 0x26, 0x9e})
				} else {
					enc[0] = 0xd1
					dec[0] = 0xd1
					mac[0] = 0xd1
				}
			}
			peerDec, _ := rc4.NewCipher(enc)
			peerEnc, _ := rc4.NewCipher(dec)
			for i := 0; i < 2; i++ {
				packet, err = w.frame()
				if err != nil {
					return err
				}
				plain := make([]byte, len(packet)-27)
				peerDec.XORKeyStream(plain, packet[27:])
				if !bytes.Equal(plain, []byte("client payload")) || !bytes.Equal(packet[19:27], blueKeepMAC(mac, plain)) {
					return fmt.Errorf("invalid client encryption/signature")
				}
				payload := []byte("server payload")
				sig := blueKeepMAC(mac, payload)
				peerEnc.XORKeyStream(payload, payload)
				data := append([]byte{8, 0, 0, 0}, sig...)
				data = append(data, payload...)
				if i == 1 {
					data[4] ^= 0xff
				} // A corrupt signature must never be accepted.
				if err = w.send(rdpTestServerData(data)); err != nil {
					return err
				}
			}
			return nil
		})
		conn, err := net.Dial("tcp", net.JoinHostPort(h, strconv.Itoa(p)))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		s := blueKeepSession{wire: &rdpWire{Conn: conn, ctx: ctx}, user: 42, channel: 1003}
		if err = s.standardSecurity(blueKeepSecurity{method: method, random: serverRandom, modulus: modulus, exponent: uint32(key.E)}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err = s.sendData([]byte("client payload"), 1003, 0); err != nil {
				t.Fatal(err)
			}
			packet, err := s.wire.frame()
			if err != nil {
				t.Fatal(err)
			}
			plain, flags, err := s.serverData(packet)
			if i == 0 && (err != nil || flags != 8 || !bytes.Equal(plain, []byte("server payload"))) {
				t.Fatalf("method=%d decrypted=%q flags=%d err=%v", method, plain, flags, err)
			}
			if i == 1 && err == nil {
				t.Fatal("corrupt message accepted")
			}
		}
		conn.Close()
		cancel()
	}
}

func TestBlueKeepMalformedServerData(t *testing.T) {
	for _, blocks := range [][]byte{
		{1, 12, 8, 0, 4, 0, 8, 0},                                       // Security block absent.
		{1, 12, 8, 0, 4, 0, 8, 0, 2, 12, 2, 0},                          // Truncated block.
		{1, 12, 8, 0, 4, 0, 8, 0, 2, 12, 12, 0, 2, 0, 0, 0, 0, 0, 0, 0}, // Encrypted but no key.
	} {
		if _, _, err := blueKeepServerData(rdpTPDU(append([]byte{0x7f, 0x66}, blocks...)), true); err == nil {
			t.Fatal("invalid GCC data accepted")
		}
	}
}
