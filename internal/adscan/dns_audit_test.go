package adscan

import (
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"testing"
	"time"
)

func dnsAuditFixture(t *testing.T, rcode dnsmessage.RCode, complete bool) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				var h [2]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				b := make([]byte, int(binary.BigEndian.Uint16(h[:])))
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				var q dnsmessage.Message
				if e := q.Unpack(b); e != nil {
					return
				}
				m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID, Response: true, RCode: rcode, RecursionAvailable: true}, Questions: q.Questions}
				if q.Questions[0].Type == 252 && rcode == 0 {
					soa := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("dc.lab.local."), MBox: dnsmessage.MustNewName("hostmaster.lab.local."), Serial: 1}}
					m.Answers = []dnsmessage.Resource{soa}
					if complete {
						m.Answers = append(m.Answers, soa)
					}
				}
				packet, e := m.Pack()
				if e != nil {
					return
				}
				binary.BigEndian.PutUint16(h[:], uint16(len(packet)))
				_, _ = c.Write(append(h[:], packet...))
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}
func TestDNSAuditDistinguishesTransferRefusalAndPartial(t *testing.T) {
	for _, tt := range []struct {
		name     string
		code     dnsmessage.RCode
		complete bool
		want     string
	}{{"complete", 0, true, "confirmed"}, {"refused", dnsmessage.RCodeRefused, false, "denied"}, {"partial", 0, false, "incomplete"}} {
		t.Run(tt.name, func(t *testing.T) {
			r, e := AuditDNS(context.Background(), "127.0.0.1", "lab.local", dnsAuditFixture(t, tt.code, tt.complete), time.Second)
			if e != nil || len(r.Checks) != 2 || r.Checks[0].State != tt.want || r.Checks[1].State != "candidate" {
				t.Fatalf("%+v %v", r, e)
			}
		})
	}
}
