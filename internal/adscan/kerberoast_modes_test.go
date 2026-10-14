package adscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"wscan/internal/domain"
)

func TestNoPreauthRoastUsesServiceASREQAndExports(t *testing.T) {
	address, count := asrepKDC(t, func(req messages.ASReq) ([]byte, error) {
		if req.ReqBody.SName.PrincipalNameString() != "HTTP/service.lab.example" || req.ReqBody.CName.PrincipalNameString() != "legacy" {
			t.Errorf("unexpected identity: %+v", req.ReqBody)
		}
		rep := asrepFixture(req, 23)
		rep.Ticket.SName = req.ReqBody.SName
		rep.Ticket.EncPart.Cipher = bytes.Repeat([]byte{0x62}, 96)
		return rep.Marshal()
	})
	o := AccessOptions{Domain: "lab.example", NoPreauthUser: "legacy", SPNs: []string{"HTTP/service.lab.example"}, DNS: DNSOptions{Servers: []string{asrepDNS(t, address)}}, ExportDir: t.TempDir()}
	// The public implementation resolves the KDC and never attempts LDAP login.
	r, err := kerberoastAccess(context.Background(), o)
	if err != nil || count.Load() != 1 || len(r.Artifacts) != 1 || len(r.Checks) != 1 || r.Checks[0].State != "confirmed" {
		t.Fatalf("report=%+v err=%v count=%d", r, err, count.Load())
	}
	b, err := os.ReadFile(r.Artifacts[0])
	if err != nil || !strings.HasPrefix(string(b), "$krb5tgs$23$*HTTP/service.lab.example$LAB.EXAMPLE$") {
		t.Fatal(string(b), err)
	}
}

func TestNoPreauthRoastStopsWhenAccountNeedsAuthentication(t *testing.T) {
	for _, code := range []int32{errorcode.KDC_ERR_PREAUTH_REQUIRED, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, errorcode.KDC_ERR_CLIENT_REVOKED} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			address, count := asrepKDC(t, func(req messages.ASReq) ([]byte, error) {
				e := messages.NewKRBError(req.ReqBody.SName, req.ReqBody.Realm, code, "")
				return e.Marshal()
			})
			o := AccessOptions{Domain: "lab.example", NoPreauthUser: "legacy", SPNs: []string{"HTTP/a", "HTTP/b"}, ExportDir: t.TempDir()}
			r, err := runNoPreauthRoastAt(context.Background(), address, o, []roastTarget{{SPN: "HTTP/a"}, {SPN: "HTTP/b"}}, AccessReport{})
			if err == nil || count.Load() != 1 || len(r.Artifacts) != 0 || r.Checks[0].State != "denied" {
				t.Fatalf("report=%+v err=%v count=%d", r, err, count.Load())
			}
		})
	}
}

func TestNoPreauthRoastRejectsUnrelatedAndMalformedTickets(t *testing.T) {
	for _, mutate := range []func(*messages.ASRep){
		func(r *messages.ASRep) { r.CName.NameString = []string{"other"} },
		func(r *messages.ASRep) { r.Ticket.SName.NameString = []string{"krbtgt", "LAB.EXAMPLE"} },
		func(r *messages.ASRep) { r.Ticket.Realm = "OTHER.EXAMPLE" },
		func(r *messages.ASRep) { r.Ticket.EncPart.EType = 3 },
		func(r *messages.ASRep) { r.Ticket.EncPart.Cipher = []byte{1} },
	} {
		address, _ := asrepKDC(t, func(req messages.ASReq) ([]byte, error) {
			r := asrepFixture(req, 23)
			r.Ticket.SName, r.Ticket.EncPart.Cipher = req.ReqBody.SName, bytes.Repeat([]byte{1}, 96)
			mutate(&r)
			return r.Marshal()
		})
		r, _ := runNoPreauthRoastAt(context.Background(), address, AccessOptions{Domain: "lab.example", NoPreauthUser: "legacy", SPNs: []string{"HTTP/a"}}, []roastTarget{{SPN: "HTTP/a"}}, AccessReport{})
		if len(r.Artifacts) != 0 || len(r.Checks) != 1 || r.Checks[0].State != "error" {
			t.Fatalf("invalid ticket accepted: %+v", r)
		}
	}
}

func TestNoPreauthAESNeedsServiceOwnerAndUsesItsSalt(t *testing.T) {
	for _, owner := range []string{"", "service"} {
		address, count := asrepKDC(t, func(req messages.ASReq) ([]byte, error) {
			if req.ReqBody.CName.PrincipalNameString() == "service" {
				info, _ := asn1.Marshal(types.ETypeInfo2{{EType: 18, Salt: "LAB.EXAMPLEOriginalService"}})
				pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}}
				e := messages.NewKRBError(req.ReqBody.SName, req.ReqBody.Realm, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")
				e.EData, _ = asn1.Marshal(pas)
				return e.Marshal()
			}
			r := asrepFixture(req, 18)
			r.Ticket.SName, r.Ticket.EncPart.Cipher = req.ReqBody.SName, bytes.Repeat([]byte{1}, 96)
			return r.Marshal()
		})
		o := AccessOptions{Domain: "lab.example", NoPreauthUser: "legacy", SPNs: []string{"HTTP/a"}, ExportDir: t.TempDir(), RPS: 20}
		r, err := runNoPreauthRoastAt(context.Background(), address, o, []roastTarget{{SPN: "HTTP/a", User: owner}}, AccessReport{})
		if err != nil || len(r.Artifacts) != 1 {
			t.Fatal(r, err)
		}
		b, _ := os.ReadFile(r.Artifacts[0])
		if owner == "" {
			var pending map[string]any
			if json.Unmarshal(b, &pending) != nil || pending["hashcat_ready"] != false || r.Checks[0].State != "incomplete" || count.Load() != 1 {
				t.Fatal(r, string(b))
			}
		} else if !strings.HasPrefix(string(b), "$krb5tgs$18$OriginalService$LAB.EXAMPLE$") || count.Load() != 2 {
			t.Fatal(r, string(b), count.Load())
		}
	}
}

func TestNoPreauthCancellationRetainsCompletedExport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address, _ := asrepKDC(t, func(req messages.ASReq) ([]byte, error) {
		r := asrepFixture(req, 23)
		r.Ticket.SName, r.Ticket.EncPart.Cipher = req.ReqBody.SName, bytes.Repeat([]byte{1}, 96)
		return r.Marshal()
	})
	o := AccessOptions{Domain: "lab.example", NoPreauthUser: "legacy", SPNs: []string{"HTTP/a", "HTTP/b"}, ExportDir: t.TempDir(), Progress: func(s string) {
		if strings.Contains(s, "HTTP/b") {
			cancel()
		}
	}}
	r, err := runNoPreauthRoastAt(ctx, address, o, []roastTarget{{SPN: "HTTP/a"}, {SPN: "HTTP/b"}}, AccessReport{})
	if !errors.Is(err, context.Canceled) || len(r.Artifacts) != 1 || len(r.Checks) != 1 || r.Checks[0].State != "confirmed" {
		t.Fatal(r, err)
	}
}

func ticketSessionFixture() roastSession {
	return roastSession{User: "alice", Realm: "LAB.EXAMPLE", Ticket: messages.Ticket{TktVNO: 5, Realm: "LAB.EXAMPLE", SName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/LAB.EXAMPLE"), EncPart: types.EncryptedData{EType: 23, Cipher: bytes.Repeat([]byte{1}, 96)}}, Key: types.EncryptionKey{KeyType: 23, KeyValue: bytes.Repeat([]byte{0x31}, 16)}, Start: time.Now().Add(-time.Minute), End: time.Now().Add(time.Hour), Flags: types.NewKrbFlags()}
}

func encodeRoastKirbi(t *testing.T, s roastSession) []byte {
	t.Helper()
	info := messages.EncKrbCredPart{TicketInfo: []messages.KrbCredInfo{{Key: s.Key, PRealm: s.Realm, PName: types.NewPrincipalName(1, s.User), SRealm: s.Ticket.Realm, SName: s.Ticket.SName, StartTime: s.Start, EndTime: s.End, Flags: s.Flags}}}
	part, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := s.Ticket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	seq, err := asn1.Marshal([]asn1.RawValue{{FullBytes: ticket}})
	if err != nil {
		t.Fatal(err)
	}
	cred := struct {
		PVNO    int                 `asn1:"explicit,tag:0"`
		MsgType int                 `asn1:"explicit,tag:1"`
		Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
		EncPart types.EncryptedData `asn1:"explicit,tag:3"`
	}{5, msgtype.KRB_CRED, asn1.RawValue{Class: asn1.ClassContextSpecific, IsCompound: true, Tag: 2, Bytes: seq}, types.EncryptedData{EType: 0, Cipher: asn1tools.AddASNAppTag(part, 29)}}
	b, err := asn1.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	return asn1tools.AddASNAppTag(b, 22)
}

func encodeRoastCache(t *testing.T, s roastSession, version byte) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write([]byte{5, version})
	write := func(v any) {
		if err := binary.Write(&b, binary.BigEndian, v); err != nil {
			t.Fatal(err)
		}
	}
	data := func(v []byte) { write(uint32(len(v))); b.Write(v) }
	principal := func(realm string, p types.PrincipalName) {
		write(p.NameType)
		write(uint32(len(p.NameString)))
		data([]byte(realm))
		for _, v := range p.NameString {
			data([]byte(v))
		}
	}
	if version == 4 {
		write(uint16(0))
	}
	principal(s.Realm, types.NewPrincipalName(1, s.User))
	principal(s.Realm, types.NewPrincipalName(1, s.User))
	principal(s.Ticket.Realm, s.Ticket.SName)
	write(uint16(s.Key.KeyType))
	if version == 3 {
		write(uint16(s.Key.KeyType))
	}
	data(s.Key.KeyValue)
	write(uint32(s.Start.Unix()))
	write(uint32(s.Start.Unix()))
	write(uint32(s.End.Unix()))
	write(uint32(s.End.Unix()))
	b.WriteByte(0)
	write(uint32(0))
	write(uint32(0))
	write(uint32(0))
	ticket, err := s.Ticket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	data(ticket)
	data(nil)
	return b.Bytes()
}

func TestKerberoastLoadsExplicitTGTWithoutPasswordOrASREQ(t *testing.T) {
	for _, format := range []string{"kirbi", "ccache3", "ccache4"} {
		t.Run(format, func(t *testing.T) {
			s := ticketSessionFixture()
			b := encodeRoastKirbi(t, s)
			if format != "kirbi" {
				b = encodeRoastCache(t, s, format[len(format)-1]-'0')
			}
			path := filepath.Join(t.TempDir(), format)
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := loadRoastSession(path, "lab.example")
			if err != nil || loaded.User != "alice" || !bytes.Equal(loaded.Key.KeyValue, s.Key.KeyValue) {
				t.Fatal(loaded.User, err)
			}
			address, count := roastFixture(t, 23, 23, nil)
			o := roastOptions(t)
			o.Credential, o.TGTFile = domain.Credential{}, path
			r, err := runKerberoastAt(context.Background(), address, o, []roastTarget{{SPN: "HTTP/service.lab.example"}}, AccessReport{})
			if err != nil || count.Load() != 1 || len(r.Artifacts) != 1 {
				t.Fatal(r, err, count.Load())
			}
		})
	}
}

func TestKerberoastRejectsInvalidTGTBeforeNetwork(t *testing.T) {
	for _, mutate := range []func(*roastSession){
		func(s *roastSession) { s.End = time.Now().Add(-time.Hour) },
		func(s *roastSession) { s.Realm = "OTHER.EXAMPLE" },
		func(s *roastSession) { s.Ticket.SName = types.NewPrincipalName(2, "HTTP/service.lab.example") },
		func(s *roastSession) { s.Key.KeyValue = []byte{1} },
		func(s *roastSession) { s.Start = time.Now().Add(time.Hour) },
	} {
		s := ticketSessionFixture()
		mutate(&s)
		path := filepath.Join(t.TempDir(), "ticket.kirbi")
		os.WriteFile(path, encodeRoastKirbi(t, s), 0600)
		if _, err := loadRoastSession(path, "lab.example"); err == nil {
			t.Fatal("invalid TGT accepted")
		}
	}
	valid := encodeRoastKirbi(t, ticketSessionFixture())
	path := filepath.Join(t.TempDir(), "broken")
	for _, b := range [][]byte{nil, {5}, {5, 4, 255, 255}, {5, 4, 0, 0, 0, 0, 0, 1, 255, 255, 255, 255}, valid[:5], append(valid, 0)} {
		os.WriteFile(path, b, 0600)
		if _, err := loadRoastSession(path, "lab.example"); err == nil {
			t.Fatal("malformed TGT accepted")
		}
	}
}

func TestKerberosWordlistsAndModeValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	os.WriteFile(path, []byte("\ufeff# comment\r\nHTTP/a|service\r\n\r\nHTTP/b\n"), 0600)
	values, err := ReadKerberosList("@"+path, 2)
	if err != nil || len(values) != 2 {
		t.Fatal(values, err)
	}
	targets, err := explicitRoastTargets(values, "lab.example", 2)
	if err != nil || targets[0].User != "service" {
		t.Fatal(targets, err)
	}
	if _, err := ReadKerberosList("@"+path, 1); err == nil {
		t.Fatal("list limit ignored")
	}
	os.WriteFile(path, bytes.Repeat([]byte{'#'}, kerberosInputLimit+1), 0600)
	if _, err := ReadKerberosList("@"+path, 5000); err == nil {
		t.Fatal("byte limit ignored")
	}
	for _, o := range []AccessOptions{
		{NoPreauthUser: "legacy", TGTFile: "file"},
		{NoPreauthUser: "legacy", Credential: domain.Credential{Username: "alice"}},
		{NoPreauthUser: "legacy", SPNs: []string{"krbtgt/LAB.EXAMPLE"}},
		{NoPreauthUser: "legacy"},
		{NoPreauthUser: "other@other.example", SPNs: []string{"HTTP/a"}},
	} {
		o.Domain = "lab.example"
		if err := ValidateKerberoastOptions(&o); err == nil {
			t.Fatal("invalid mode accepted", o.NoPreauthUser)
		}
	}
}
