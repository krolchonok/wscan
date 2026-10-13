package adscan

import (
	"context"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestDiscoverLDAPIdentityOnlyReadsRootDSE(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
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
		c.SetDeadline(time.Now().Add(time.Second))
		req, err := ber.ReadPacket(c)
		if err != nil {
			done <- err
			return
		}
		if len(req.Children) < 2 || req.Children[1].Tag != 3 || req.Children[1].Children[0].Value != "" {
			t.Error("identity probe performed bind or non-RootDSE search")
		}
		id := req.Children[0].Value.(int64)
		send := func(op *ber.Packet) error {
			m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
			m.AppendChild(op)
			_, err := c.Write(m.Bytes())
			return err
		}
		entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
		entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		for _, attr := range [][2]string{{"defaultNamingContext", "DC=lab,DC=example"}, {"dnsHostName", "dc.lab.example"}, {"supportedCapabilities", "1.2.840.113556.1.4.800"}} {
			p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr[0], ""))
			v := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
			v.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr[1], ""))
			p.AppendChild(v)
			attrs.AppendChild(p)
		}
		entry.AppendChild(attrs)
		if err := send(entry); err != nil {
			done <- err
			return
		}
		result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "")
		result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
		result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		if err := send(result); err != nil {
			done <- err
			return
		}
		if next, err := ber.ReadPacket(c); err == nil {
			t.Errorf("extra LDAP request after RootDSE: %+v", next)
		}
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	host, err := DiscoverLDAPIdentity(ctx, "127.0.0.1", l.Addr().(*net.TCPAddr).Port)
	if err != nil || !host.DCConfirmed || host.Domain != "lab.example" || host.HostName != "dc.lab.example" || len(host.LDAPUsers) != 0 {
		t.Fatalf("%+v %v", host, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
