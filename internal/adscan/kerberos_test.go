package adscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"golang.org/x/net/dns/dnsmessage"
)

func asrepFixture(req messages.ASReq, etype int32) messages.ASRep {
	cipher := make([]byte, 40)
	for i := range cipher {
		cipher[i] = byte(i)
	}
	return messages.ASRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: msgtype.KRB_AS_REP, CRealm: req.ReqBody.Realm, CName: req.ReqBody.CName,
		Ticket:  messages.Ticket{TktVNO: 5, Realm: req.ReqBody.Realm, SName: types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", req.ReqBody.Realm}}, EncPart: types.EncryptedData{EType: etype, Cipher: bytes.Repeat([]byte{0x42}, 40)}},
		EncPart: types.EncryptedData{EType: etype, Cipher: cipher}}}
}

func asrepKDC(t *testing.T, handler func(messages.ASReq) ([]byte, error)) (string, *atomic.Int32) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Int32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				var header [4]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					t.Error(err)
					return
				}
				n := binary.BigEndian.Uint32(header[:])
				if n == 0 || n > 65536 {
					t.Errorf("request size %d", n)
					return
				}
				packet := make([]byte, n)
				if _, err := io.ReadFull(conn, packet); err != nil {
					t.Error(err)
					return
				}
				var req messages.ASReq
				if err := req.Unmarshal(packet); err != nil {
					t.Error(err)
					return
				}
				if req.PVNO != 5 || req.MsgType != msgtype.KRB_AS_REQ || len(req.PAData) != 0 {
					t.Errorf("request contains authentication/pre-auth: %+v", req)
					return
				}
				count.Add(1)
				reply, err := handler(req)
				if err != nil {
					t.Error(err)
					return
				}
				binary.BigEndian.PutUint32(header[:], uint32(len(reply)))
				// Fragment both the record marker and ASN.1 body.
				for _, part := range [][]byte{header[:1], header[1:3], header[3:], reply[:min(3, len(reply))], reply[min(3, len(reply)):]} {
					if _, err := conn.Write(part); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); <-done })
	return l.Addr().String(), count
}

func TestASREPProgressExplainsPreauthAndRequestErrors(t *testing.T) {
	for _, code := range []int32{errorcode.KDC_ERR_PREAUTH_REQUIRED, errorcode.KDC_ERR_POLICY} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			address, _ := asrepKDC(t, func(req messages.ASReq) ([]byte, error) {
				reply := messages.NewKRBError(req.ReqBody.SName, req.ReqBody.Realm, code, "")
				return reply.Marshal()
			})
			var journal []string
			report, err := runASREPAt(context.Background(), address, "lab.example", []string{"alice"}, AccessOptions{Timeout: time.Second, Progress: func(s string) { journal = append(journal, s) }}, AccessReport{})
			if err != nil || len(report.Checks) != 1 {
				t.Fatalf("%+v %v", report, err)
			}
			want := "KDC требует pre-auth"
			if code == errorcode.KDC_ERR_POLICY {
				want = "ошибка запроса к " + address
			}
			if !strings.Contains(strings.Join(journal, "\n"), want) {
				t.Fatalf("KDC outcome hidden: %v", journal)
			}
		})
	}
}

func TestASREPKDCOutcomesAndNoPassword(t *testing.T) {
	for _, tc := range []struct {
		code  int32
		state string
	}{{0, "confirmed"}, {errorcode.KDC_ERR_PREAUTH_REQUIRED, "negative"}, {errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "negative"}, {errorcode.KDC_ERR_CLIENT_REVOKED, "denied"}, {errorcode.KDC_ERR_POLICY, "error"}} {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			address, count := asrepKDC(t, func(req messages.ASReq) ([]byte, error) {
				if !reflect.DeepEqual(req.ReqBody.EType, []int32{23}) {
					t.Errorf("unexpected etypes %v", req.ReqBody.EType)
				}
				if tc.code != 0 {
					e := messages.NewKRBError(req.ReqBody.SName, req.ReqBody.Realm, tc.code, "")
					return e.Marshal()
				}
				rep := asrepFixture(req, 23)
				return rep.Marshal()
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			state, hash, err := probeASREP(ctx, address, "lab.example", "alice")
			if tc.state == "error" {
				if err == nil {
					t.Fatal("KDC policy error hidden")
				}
				return
			}
			if err != nil || state != tc.state || count.Load() != 1 {
				t.Fatalf("%s %s %v (%d)", state, hash, err, count.Load())
			}
			if tc.code == 0 && hash != "$krb5asrep$23$alice@LAB.EXAMPLE:000102030405060708090a0b0c0d0e0f$101112131415161718191a1b1c1d1e1f2021222324252627" {
				t.Fatal(hash)
			}
		})
	}
}

func TestASREPAESFallbackAndHashcatLayout(t *testing.T) {
	for _, etype := range []int32{17, 18} {
		t.Run(fmt.Sprint(etype), func(t *testing.T) {
			address, count := asrepKDC(t, func(req messages.ASReq) ([]byte, error) {
				if reflect.DeepEqual(req.ReqBody.EType, []int32{23}) {
					e := messages.NewKRBError(req.ReqBody.SName, req.ReqBody.Realm, errorcode.KDC_ERR_ETYPE_NOSUPP, "")
					return e.Marshal()
				}
				if !reflect.DeepEqual(req.ReqBody.EType, []int32{18, 17}) {
					t.Error(req.ReqBody.EType)
				}
				rep := asrepFixture(req, etype)
				return rep.Marshal()
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			state, hash, err := probeASREP(ctx, address, "lab.example", "alice")
			want := fmt.Sprintf("$krb5asrep$%d$alice$LAB.EXAMPLE$1c1d1e1f2021222324252627$000102030405060708090a0b0c0d0e0f101112131415161718191a1b", etype)
			if err != nil || state != "confirmed" || hash != want || count.Load() != 2 {
				t.Fatalf("%s %s %v (%d)", state, hash, err, count.Load())
			}
		})
	}
}

func TestASREPRejectsMismatchedAndMalformedReplies(t *testing.T) {
	for _, mutate := range []func(*messages.ASRep){func(r *messages.ASRep) { r.CName.NameString[0] = "bob" }, func(r *messages.ASRep) { r.CRealm = "OTHER.EXAMPLE" }, func(r *messages.ASRep) { r.Ticket.SName.NameString[0] = "cifs" }, func(r *messages.ASRep) { r.EncPart.Cipher = []byte{1} }, func(r *messages.ASRep) { r.EncPart.EType = 18 }} {
		address, _ := asrepKDC(t, func(req messages.ASReq) ([]byte, error) { r := asrepFixture(req, 23); mutate(&r); return r.Marshal() })
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		state, hash, err := probeASREP(ctx, address, "lab.example", "alice")
		cancel()
		if err == nil || state == "confirmed" || hash != "" {
			t.Fatalf("invalid reply accepted: %s %s %v", state, hash, err)
		}
	}
	address, _ := asrepKDC(t, func(messages.ASReq) ([]byte, error) { return []byte{1, 2, 3}, nil })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if state, _, err := probeASREP(ctx, address, "lab.example", "alice"); err == nil || state == "confirmed" {
		t.Fatalf("malformed reply: %s %v", state, err)
	}
}

func TestKerberosTCPCancellationAndLengthBounds(t *testing.T) {
	for _, length := range []uint32{0, 1<<20 + 1, 0x80000000} {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, e := l.Accept()
			if e != nil {
				return
			}
			defer c.Close()
			b := make([]byte, 6)
			io.ReadFull(c, b)
			binary.BigEndian.PutUint32(b, length)
			c.Write(b[:4])
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if _, err := kerberosTCP(ctx, l.Addr().String(), []byte{1, 2}); err == nil {
			t.Fatal("bad length accepted")
		}
		cancel()
		l.Close()
		<-done
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ready, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 6)
		io.ReadFull(c, b)
		close(ready)
		io.Copy(io.Discard, c)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, e := kerberosTCP(ctx, l.Addr().String(), []byte{1, 2}); result <- e }()
	<-ready
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancel did not close connection")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation stalled")
	}
	<-done
}

func TestASREPUserNormalizationAndRealmIsolation(t *testing.T) {
	users, err := NormalizeASREPUsers([]string{"Alice", "alice", "LAB\\bob", "carol@lab.example", "machine$", ""}, "lab.example", 4)
	if err != nil || !reflect.DeepEqual(users, []string{"Alice", "bob", "carol", "machine$"}) {
		t.Fatalf("%v %v", users, err)
	}
	for _, users := range [][]string{{"alice@other.example"}, {"OTHER\\alice"}, {"alice:bob"}, {"lab\\"}, {"a", "b", "c"}} {
		if _, err := NormalizeASREPUsers(users, "lab.example", 2); err == nil {
			t.Fatalf("invalid names accepted: %v", users)
		}
	}
}

func asrepDNS(t *testing.T, kdcAddress string) string {
	t.Helper()
	_, port, _ := net.SplitHostPort(kdcAddress)
	var kdcPort uint16
	fmt.Sscan(port, &kdcPort)
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, peer, e := l.ReadFrom(buf)
			if e != nil {
				return
			}
			var p dnsmessage.Parser
			h, e := p.Start(buf[:n])
			if e != nil {
				continue
			}
			q, e := p.Question()
			if e != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionAvailable: true})
			b.EnableCompression()
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 1}
			switch q.Type {
			case dnsmessage.TypeSRV:
				target, _ := dnsmessage.NewName("dc.lab.example.")
				b.SRVResource(rh, dnsmessage.SRVResource{Target: target, Port: kdcPort})
			case dnsmessage.TypeA:
				b.AResource(rh, dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
			}
			reply, e := b.Finish()
			if e == nil {
				l.WriteTo(reply, peer)
			}
		}
	}()
	t.Cleanup(func() { l.Close(); <-done })
	return l.LocalAddr().String()
}

func TestASREPAutoDNSAndPrivateExport(t *testing.T) {
	address, count := asrepKDC(t, func(req messages.ASReq) ([]byte, error) { rep := asrepFixture(req, 23); return rep.Marshal() })
	dir := t.TempDir()
	r, err := RunAccess(context.Background(), AccessOptions{Mode: "asrep", Domain: "lab.example", Users: []string{"alice", "ALICE"}, DNS: DNSOptions{Servers: []string{asrepDNS(t, address)}}, ExportDir: dir})
	if err != nil || len(r.Checks) != 1 || r.Checks[0].State != "confirmed" || len(r.Artifacts) != 1 || count.Load() != 1 || r.Endpoint != "tcp://"+address {
		t.Fatalf("report %+v err %v count %d", r, err, count.Load())
	}
	data, err := os.ReadFile(r.Artifacts[0])
	if err != nil || !strings.HasPrefix(string(data), "$krb5asrep$23$") {
		t.Fatalf("export %s %v", data, err)
	}
	stat, err := os.Stat(r.Artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && stat.Mode().Perm() != 0600 {
		t.Fatal(stat.Mode())
	}
}

func TestASREPReconUsesOneKDCPerRealmAndKeepsScope(t *testing.T) {
	r := Result{Hosts: []Host{{Address: "10.0.0.10", Domain: "a.example", Ports: []int{88}, LDAPUsers: []string{"alice"}}, {Address: "10.0.0.11", Domain: "a.example", Ports: []int{88}, LDAPUsers: []string{"alice", "bob"}}, {Address: "10.0.0.12", Domain: "b.example", Ports: []int{88}, LDAPUsers: []string{"carol"}}, {Address: "10.0.0.13", Domain: "empty.example", Ports: []int{88}}}, DNSRecords: []SRVRecord{{Domain: "a.example", Target: "outside.example", Port: 88}}}
	opts, skipped := ASREPReconOptions(r)
	if len(opts) != 2 || len(skipped) != 1 || opts[0].Host != "10.0.0.10" || !reflect.DeepEqual(opts[0].Users, []string{"alice", "bob"}) || !reflect.DeepEqual(opts[1].Users, []string{"carol"}) {
		t.Fatalf("%+v %v", opts, skipped)
	}
}
