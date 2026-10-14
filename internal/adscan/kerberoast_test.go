package adscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"wscan/internal/domain"
)

func roastFixture(t *testing.T, authEtype, ticketEtype int32, mutate func(*messages.TGSRep)) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int32{}
	done := make(chan struct{})
	realm := "LAB.EXAMPLE"
	session := types.EncryptionKey{KeyType: 23, KeyValue: bytes.Repeat([]byte{0x31}, 16)}
	go func() {
		defer close(done)
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				var header [4]byte
				if _, e = io.ReadFull(conn, header[:]); e != nil {
					return
				}
				n := binary.BigEndian.Uint32(header[:])
				if n > 65536 {
					t.Error("oversized request")
					return
				}
				packet := make([]byte, n)
				if _, e = io.ReadFull(conn, packet); e != nil {
					return
				}
				count.Add(1)
				var reply []byte
				var req messages.ASReq
				if e = req.Unmarshal(packet); e == nil {
					etype := authEtype
					user := req.ReqBody.CName.NameString[0]
					if user != "alice" {
						etype = req.ReqBody.EType[0]
					}
					info, er := asn1.Marshal(types.ETypeInfo2{{EType: etype, Salt: realm + user}})
					if er != nil {
						t.Error(er)
						return
					}
					pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}}
					if !req.PAData.Contains(patype.PA_ENC_TIMESTAMP) {
						ke := messages.NewKRBError(req.ReqBody.SName, realm, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")
						ke.CName = req.ReqBody.CName
						ke.CRealm = realm
						ke.EData, _ = asn1.Marshal(pas)
						reply, e = ke.Marshal()
					} else {
						key, _, er := crypto.GetKeyFromPassword("Correct8!", req.ReqBody.CName, realm, etype, pas)
						if er != nil {
							t.Error(er)
							return
						}
						var timestamp types.EncryptedData
						for _, pa := range req.PAData {
							if pa.PADataType == patype.PA_ENC_TIMESTAMP {
								er = timestamp.Unmarshal(pa.PADataValue)
							}
						}
						if er == nil {
							_, er = crypto.DecryptEncPart(timestamp, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP)
						}
						if er != nil {
							ke := messages.NewKRBError(req.ReqBody.SName, realm, errorcode.KDC_ERR_PREAUTH_FAILED, "")
							reply, e = ke.Marshal()
						} else {
							now := time.Now().UTC()
							part := messages.EncKDCRepPart{Key: session, LastReqs: []messages.LastReq{{LRType: 0, LRValue: now}}, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), SRealm: realm, SName: req.ReqBody.SName}
							plain, er := part.Marshal()
							if er != nil {
								t.Error(er)
								return
							}
							rep := asrepFixture(req, etype)
							rep.PAData = pas
							rep.EncPart, er = crypto.GetEncryptedData(plain, key, keyusage.AS_REP_ENCPART, 1)
							if er != nil {
								t.Error(er)
								return
							}
							reply, e = rep.Marshal()
						}
					}
				} else {
					var req messages.TGSReq
					if er := req.Unmarshal(packet); er != nil {
						t.Error(er)
						return
					}
					if !req.PAData.Contains(patype.PA_TGS_REQ) {
						t.Error("missing TGS authenticator")
						return
					}
					now := time.Now().UTC()
					part := messages.EncKDCRepPart{Key: session, LastReqs: []messages.LastReq{{LRType: 0, LRValue: now}}, Nonce: req.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), SRealm: realm, SName: req.ReqBody.SName}
					plain, er := part.Marshal()
					if er != nil {
						t.Error(er)
						return
					}
					enc, er := crypto.GetEncryptedData(plain, session, keyusage.TGS_REP_ENCPART_SESSION_KEY, 1)
					if er != nil {
						t.Error(er)
						return
					}
					rep := messages.TGSRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: msgtype.KRB_TGS_REP, CRealm: realm, CName: req.ReqBody.CName, Ticket: messages.Ticket{TktVNO: 5, Realm: realm, SName: req.ReqBody.SName, EncPart: types.EncryptedData{EType: ticketEtype, Cipher: bytes.Repeat([]byte{0x62}, 96)}}, EncPart: enc}}
					if mutate != nil {
						mutate(&rep)
					}
					reply, e = rep.Marshal()
				}
				if e != nil {
					t.Error(e)
					return
				}
				binary.BigEndian.PutUint32(header[:], uint32(len(reply)))
				for _, part := range [][]byte{header[:1], header[1:], reply[:2], reply[2:]} {
					if _, e = conn.Write(part); e != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return listener.Addr().String(), count
}

func roastOptions(t *testing.T) AccessOptions {
	return AccessOptions{Domain: "lab.example", Credential: domain.Credential{Type: "password", Username: "alice", Secret: "Correct8!"}, TGSEtypes: []int32{18, 17, 23}, RPS: 20, Timeout: time.Second, ExportDir: t.TempDir()}
}

func TestKerberoastAuthenticatedExchangeAndExport(t *testing.T) {
	for _, v := range []struct {
		auth, ticket int32
		hash         bool
	}{{23, 23, false}, {17, 17, false}, {18, 18, false}, {23, 23, true}} {
		t.Run(fmt.Sprintf("%d-%d-hash%v", v.auth, v.ticket, v.hash), func(t *testing.T) {
			address, count := roastFixture(t, v.auth, v.ticket, nil)
			o := roastOptions(t)
			if v.hash {
				key, _, e := crypto.GetKeyFromPassword(o.Credential.Secret, types.NewPrincipalName(1, "alice"), "LAB.EXAMPLE", 23, nil)
				if e != nil {
					t.Fatal(e)
				}
				o.Credential.Type = "ntlm-hash"
				o.Credential.Secret = hex.EncodeToString(key.KeyValue)
			}
			r, e := runKerberoastAt(context.Background(), address, o, []roastTarget{{User: "service", SPN: "HTTP/service.lab.example"}}, AccessReport{})
			if e != nil || len(r.Artifacts) != 1 {
				t.Fatalf("report=%+v err=%v", r, e)
			}
			b, e := os.ReadFile(r.Artifacts[0])
			if e != nil || !strings.HasPrefix(string(b), fmt.Sprintf("$krb5tgs$%d$", v.ticket)) {
				t.Fatal(string(b), e)
			}
			info, _ := os.Stat(r.Artifacts[0])
			if info.Mode().Perm() != 0600 {
				t.Fatal(info.Mode())
			}
			want := int32(3)
			if v.ticket != 23 {
				want++
			}
			if count.Load() != want {
				t.Fatalf("requests=%d want=%d", count.Load(), want)
			}
			for _, check := range r.Checks {
				if strings.Contains(check.Evidence, o.Credential.Secret) {
					t.Fatal("secret disclosed")
				}
			}
		})
	}
}

func TestKerberoastBadCredentialStopsWithoutRetry(t *testing.T) {
	address, count := roastFixture(t, 23, 23, nil)
	o := roastOptions(t)
	o.Credential.Secret = "wrong"
	r, e := runKerberoastAt(context.Background(), address, o, []roastTarget{{User: "service", SPN: "HTTP/service.lab.example"}}, AccessReport{})
	if e == nil || count.Load() != 2 || len(r.Artifacts) > 0 {
		t.Fatal(r, e, count.Load())
	}
}

func TestKerberoastRejectsMismatchedOrCorruptReply(t *testing.T) {
	for _, mutate := range []func(*messages.TGSRep){func(r *messages.TGSRep) { r.Ticket.SName.NameString = []string{"HTTP", "other.lab.example"} }, func(r *messages.TGSRep) { r.EncPart.Cipher[3] ^= 0x80 }, func(r *messages.TGSRep) {
		key := types.EncryptionKey{KeyType: 23, KeyValue: bytes.Repeat([]byte{0x31}, 16)}
		if e := r.DecryptEncPart(key); e != nil {
			t.Fatal(e)
		}
		r.DecryptedEncPart.Nonce++
		plain, e := r.DecryptedEncPart.Marshal()
		if e != nil {
			t.Fatal(e)
		}
		r.EncPart, e = crypto.GetEncryptedData(plain, key, keyusage.TGS_REP_ENCPART_SESSION_KEY, 1)
		if e != nil {
			t.Fatal(e)
		}
	}} {
		address, _ := roastFixture(t, 23, 23, mutate)
		o := roastOptions(t)
		r, e := runKerberoastAt(context.Background(), address, o, []roastTarget{{User: "service", SPN: "HTTP/service.lab.example"}}, AccessReport{})
		if e != nil || len(r.Artifacts) > 0 {
			t.Fatal(r, e)
		}
		for _, c := range r.Checks {
			if c.State == "confirmed" {
				t.Fatal("invalid ticket accepted")
			}
		}
	}
}

func TestKerberoastCancellationKeepsCompletedHash(t *testing.T) {
	address, count := roastFixture(t, 23, 23, nil)
	o := roastOptions(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.Progress = func(s string) {
		if strings.Contains(s, "second") {
			cancel()
		}
	}
	r, e := runKerberoastAt(ctx, address, o, []roastTarget{{User: "service", SPN: "HTTP/first"}, {User: "service", SPN: "HTTP/second"}}, AccessReport{})
	if e != context.Canceled || len(r.Artifacts) != 1 || count.Load() != 3 {
		t.Fatal(r, e, count.Load())
	}
}

func TestTGSCiphertextHashcatBoundariesAndSalt(t *testing.T) {
	cipher := make([]byte, 80)
	for i := range cipher {
		cipher[i] = byte(i)
	}
	ticket := messages.Ticket{Realm: "LAB.EXAMPLE", SName: types.NewPrincipalName(2, "HTTP/service"), EncPart: types.EncryptedData{EType: 23, Cipher: cipher}}
	hash, e := tgsHash(ticket, "service", "service")
	want := "$krb5tgs$23$*service$LAB.EXAMPLE$HTTP/service*$" + hex.EncodeToString(cipher[:16]) + "$" + hex.EncodeToString(cipher[16:])
	if e != nil || hash != want {
		t.Fatal(hash, e)
	}
	for _, etype := range []int32{17, 18} {
		ticket.EncPart.EType = etype
		hash, e = tgsHash(ticket, "MACHINE$", "hostmachine.lab.example")
		want = fmt.Sprintf("$krb5tgs$%d$hostmachine.lab.example$LAB.EXAMPLE$%s$%s", etype, hex.EncodeToString(cipher[68:]), hex.EncodeToString(cipher[:68]))
		if e != nil || hash != want {
			t.Fatal(hash, e)
		}
	}
	ticket.EncPart.Cipher = []byte{1}
	if _, e = tgsHash(ticket, "service", "service"); e == nil {
		t.Fatal("short cipher exported")
	}
	for _, spn := range []string{"krbtgt/LAB.EXAMPLE", "HTTP/*", "HTTP/host@other.realm", "HTTP/", "HTTP/host\nBAD"} {
		if _, e := normalizeSPNs([]string{spn}, 1); e == nil {
			t.Fatal(spn)
		}
	}
}

func TestKerberoastUntrustedIterationLimit(t *testing.T) {
	for _, n := range []uint32{0, 1000001, 0xffffffff} {
		params := make([]byte, 4)
		binary.BigEndian.PutUint32(params, n)
		data, e := asn1.Marshal(types.ETypeInfo2{{EType: 18, Salt: "LAB.EXAMPLEalice", S2KParams: params}})
		if e != nil {
			t.Fatal(e)
		}
		if e = validatePAIterations(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: data}}); e == nil {
			t.Fatal(n)
		}
	}
}
