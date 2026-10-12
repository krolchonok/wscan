package adscan

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// A local directory exposes RootDSE while rejecting anonymous user enumeration.
// Exercise both LDAP and LDAPS without requiring an actual AD or privileged port.
func TestRootDSEKeepsDomainWhenAnonymousUsersAreDenied(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(strconv.FormatBool(secure), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			if secure {
				certServer := httptest.NewTLSServer(nil)
				config := certServer.TLS.Clone()
				certServer.Close()
				listener = tls.NewListener(listener, config)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				for i := 0; i < 2; i++ {
					request, err := ber.ReadPacket(conn)
					if err != nil {
						done <- err
						return
					}
					id := request.Children[0].Value.(int64)
					send := func(op *ber.Packet) error {
						message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
						message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
						message.AppendChild(op)
						_, err := conn.Write(message.Bytes())
						return err
					}
					if i == 0 {
						entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
						entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
						attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
						for _, attr := range [][2]string{{"defaultNamingContext", "DC=lab,DC=example"}, {"dnsHostName", "dc.lab.example"}, {"supportedCapabilities", "1.2.840.113556.1.4.800"}} {
							pair := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
							pair.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr[0], ""))
							values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
							values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr[1], ""))
							pair.AppendChild(values)
							attrs.AppendChild(pair)
						}
						entry.AppendChild(attrs)
						if err := send(entry); err != nil {
							done <- err
							return
						}
					}
					result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "")
					code := int64(0)
					if i == 1 {
						code = 50
					}
					result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
					result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
					result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
					if err := send(result); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			port := listener.Addr().(*net.TCPAddr).Port
			info := rootDSEAt(context.Background(), "127.0.0.1", port, secure)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !info.DCConfirmed || len(info.Identity) != 3 || info.Domain != "lab.example" || info.HostName != "dc.lab.example" || len(info.Users) != 0 || !strings.Contains(info.Message, "Insufficient Access Rights") {
				t.Fatalf("lost RootDSE or LDAP denial: %+v", info)
			}
		})
	}
}
func TestLDAPPortIncludesTLSOnlyDirectory(t *testing.T) {
	for _, tc := range []struct {
		ports []int
		want  int
	}{{[]int{445, 636}, 636}, {[]int{3269}, 3269}, {[]int{389, 636}, 389}, {[]int{445}, 0}} {
		if got := ldapPort(tc.ports); got != tc.want {
			t.Fatalf("%v: got %d", tc.ports, got)
		}
	}
}
