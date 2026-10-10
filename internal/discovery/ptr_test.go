package discovery

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestScanPTRSelectedServerAndWholeSubnet(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	queries := make(chan string, 8)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var msg dnsmessage.Message
			if msg.Unpack(buf[:n]) != nil {
				return
			}
			queries <- msg.Questions[0].Name.String()
			msg.Response = true
			if strings.HasPrefix(msg.Questions[0].Name.String(), "1.") {
				name, _ := dnsmessage.NewName("workstation.lab.")
				msg.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: msg.Questions[0].Name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}, Body: &dnsmessage.PTRResource{PTR: name}}}
			} else {
				msg.RCode = dnsmessage.RCodeNameError
			}
			packet, _ := msg.Pack()
			conn.WriteTo(packet, peer)
		}
	}()
	var done, total int
	names, failures, err := ScanPTR(context.Background(), []string{"192.0.2.0/30"}, conn.LocalAddr().String(), 2, 1000, time.Second, func(d, n int) { done, total = d, n })
	if err != nil || len(failures) != 0 {
		t.Fatalf("%v %v", err, failures)
	}
	if done != 4 || total != 4 || len(names) != 4 || len(queries) != 4 {
		t.Fatalf("incomplete subnet: %d/%d %v", done, total, names)
	}
	if got := names["192.0.2.1"]; len(got) != 1 || got[0] != "workstation.lab" {
		t.Fatalf("names: %v", names)
	}
}

func TestPTRValidationAndCancellation(t *testing.T) {
	for _, server := range []string{"", "dns.example", "127.0.0.1:0", "127.0.0.1:65536"} {
		if _, err := DNSServerAddress(server); err == nil {
			t.Fatalf("accepted %q", server)
		}
	}
	for _, server := range []string{"127.0.0.1", "::1", "[::1]:5353"} {
		if _, err := DNSServerAddress(server); err != nil {
			t.Fatal(err)
		}
	}
	for _, cidr := range []string{"10.0.0.0/8", "::/64", "bad"} {
		if _, _, err := ScanPTR(context.Background(), []string{cidr}, "127.0.0.1", 1, 1, time.Second, nil); err == nil {
			t.Fatalf("accepted %q", cidr)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ScanPTR(ctx, []string{"192.0.2.0/24"}, "127.0.0.1", 2, 1, time.Second, nil); err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
}

func TestQueryPTRIPv6AndTimeout(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	queries := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var msg dnsmessage.Message
		if msg.Unpack(buf[:n]) == nil {
			queries <- msg.Questions[0].Name.String()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := queryPTR(ctx, "2001:db8::1", conn.LocalAddr().String(), time.Second); err == nil {
		t.Fatal("missing timeout")
	}
	select {
	case name := <-queries:
		if !strings.HasPrefix(name, "1.0.0.0.") || !strings.HasSuffix(name, "8.b.d.0.1.0.0.2.ip6.arpa.") {
			t.Fatal(name)
		}
	default:
		t.Fatal("no query")
	}
}

func TestQueryPTRRetriesTruncatedUDPOverTCP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 4096)
		n, peer, err := udp.ReadFrom(buf)
		if err != nil {
			return
		}
		var msg dnsmessage.Message
		if msg.Unpack(buf[:n]) != nil {
			return
		}
		msg.Response = true
		msg.Truncated = true
		packet, _ := msg.Pack()
		udp.WriteTo(packet, peer)
	}()
	go func() {
		conn, err := tcp.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		packet := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, packet); err != nil {
			return
		}
		var msg dnsmessage.Message
		if msg.Unpack(packet) != nil {
			return
		}
		msg.Response = true
		name, _ := dnsmessage.NewName("tcp.lab.")
		msg.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: msg.Questions[0].Name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}, Body: &dnsmessage.PTRResource{PTR: name}}}
		packet, _ = msg.Pack()
		binary.BigEndian.PutUint16(size[:], uint16(len(packet)))
		conn.Write(size[:])
		conn.Write(packet)
	}()
	names, err := queryPTR(context.Background(), "192.0.2.1", tcp.Addr().String(), time.Second)
	if err != nil || len(names) != 1 || names[0] != "tcp.lab." {
		t.Fatalf("TCP fallback: %v %v", names, err)
	}
}
