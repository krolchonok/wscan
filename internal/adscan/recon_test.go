package adscan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDCRoleRequiresADDSAndDoesNotInferFromNames(t *testing.T) {
	for _, host := range []Host{
		{HostName: "member.lab.example", Domain: "lab.example", Ports: []int{445}},
		{HostName: "ldap.lab.example", Domain: "lab.example", Ports: []int{389}},
		{Ports: []int{88, 389}},
		{DCDNSAdvertised: true, Ports: []int{445}},
	} {
		if rolePresent(classifyRoles(host), "Контроллер домена") {
			t.Fatalf("unconfirmed host marked DC: %+v", host)
		}
	}
	if !rolePresent(classifyRoles(Host{DCConfirmed: true, Ports: []int{636}}), "Контроллер домена") {
		t.Fatal("confirmed DC missing")
	}
	for _, capabilities := range [][]string{nil, {"1.2.840.113556.1.4.1851"}, {"1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1851"}} {
		if hasADDSCapability(capabilities) {
			t.Fatalf("AD LDS/generic LDAP considered AD DS: %v", capabilities)
		}
	}
	if !hasADDSCapability([]string{"1.2.840.113556.1.4.800"}) {
		t.Fatal("AD DS capability not recognized")
	}
}

// Each local DNS server answers SRV and A, including names outside the scan scope.
func reconDNSServer(t *testing.T, answers int) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, address, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var parser dnsmessage.Parser
			header, err := parser.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := parser.Question()
			if err != nil {
				continue
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true, RecursionAvailable: true})
			builder.EnableCompression()
			if builder.StartQuestions() != nil || builder.Question(q) != nil || builder.StartAnswers() != nil {
				continue
			}
			rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 30}
			switch q.Type {
			case dnsmessage.TypeSRV:
				rh.Type = dnsmessage.TypeSRV
				for i := 0; i < answers; i++ {
					name, _ := dnsmessage.NewName(fmt.Sprintf("dc%d.lab.example.", i))
					if err := builder.SRVResource(rh, dnsmessage.SRVResource{Port: 389, Target: name}); err != nil {
						break
					}
				}
			case dnsmessage.TypeA:
				rh.Type = dnsmessage.TypeA
				ip := [4]byte{10, 20, 0, 10}
				if strings.HasPrefix(q.Name.String(), "dc1.") {
					ip = [4]byte{10, 30, 0, 11}
				}
				_ = builder.AResource(rh, dnsmessage.AResource{A: ip})
			}
			packet, err := builder.Finish()
			if err == nil {
				_, _ = conn.WriteTo(packet, address)
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return conn.LocalAddr().String()
}

func TestSRVCoversMoreThanFourServersAndDomains(t *testing.T) {
	var servers []string
	for i := 0; i < 5; i++ {
		servers = append(servers, reconDNSServer(t, 1))
	}
	domains := []string{"a.example", "b.example", "c.example", "d.example", "e.example"}
	records, diagnostics, err := LookupADSRVWithOptions(context.Background(), nil, DNSOptions{Servers: servers, Domains: domains})
	if err != nil || len(diagnostics) != 0 {
		t.Fatalf("lookup: %v %v", err, diagnostics)
	}
	seen := map[string]bool{}
	for _, record := range records {
		seen[net.JoinHostPort(record.Server, fmt.Sprint(record.ServerPort))+"|"+record.Domain] = true
	}
	for _, server := range servers {
		for _, domain := range domains {
			if !seen[server+"|"+domain] {
				t.Errorf("missing server/domain %s %s", server, domain)
			}
		}
	}
}

func TestDNSCoverageAndAnswerLimitsAreVisible(t *testing.T) {
	server := reconDNSServer(t, 3)
	records, diagnostics, err := LookupADSRVWithOptions(context.Background(), nil, DNSOptions{Servers: []string{server}, Domains: []string{"lab.example"}, MaxQueries: 2, MaxAnswers: 1})
	if err != nil || len(records) != 2 {
		t.Fatalf("partial records: %v %+v", err, records)
	}
	text := strings.Join(diagnostics, "\n")
	if !strings.Contains(text, "покрытие неполное") || !strings.Contains(text, "лимит SRV-ответов") {
		t.Fatalf("limits hidden: %s", text)
	}
}

func TestDNSIdentityPreservesScopeAndProvenance(t *testing.T) {
	server := reconDNSServer(t, 2)
	records, _, err := LookupADSRVWithOptions(context.Background(), nil, DNSOptions{Servers: []string{server}, Domains: []string{"lab.example"}})
	if err != nil {
		t.Fatal(err)
	}
	result := Result{CIDR: "10.20.0.0/24", Hosts: []Host{{Address: "10.20.0.10", Ports: []int{445}}}, DNSRecords: records}
	if err := enrichDNSIdentity(context.Background(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Hosts) != 1 || result.Hosts[0].Address != "10.20.0.10" {
		t.Fatalf("scope expanded: %+v", result.Hosts)
	}
	host := result.Hosts[0]
	if host.Domain != "lab.example" || host.HostName != "dc0.lab.example" || host.DCConfirmed || !host.DCDNSAdvertised || !rolePresent(host.Roles, "Предполагаемый контроллер домена") {
		t.Fatalf("DNS role/identity wrong: %+v", host)
	}
	if len(host.Identity) == 0 || !strings.Contains(host.Identity[0].Source, server) {
		t.Fatalf("source missing: %+v", host.Identity)
	}
	// A conflicting DNS observation must not overwrite LDAP identity.
	result.Hosts[0].Domain = "other.example"
	if err := enrichDNSIdentity(context.Background(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Hosts[0].Domain != "other.example" {
		t.Fatal("DNS overwrote prior identity")
	}
}

func TestDNSValidationAndCancellation(t *testing.T) {
	for _, options := range []DNSOptions{
		{Servers: []string{"dns.example"}}, {Servers: []string{"127.0.0.1:0"}}, {Domains: []string{"bad/name"}}, {Domains: []string{"-bad.example"}}, {MaxQueries: -1},
	} {
		if _, err := ValidateDNSOptions(options); err == nil {
			t.Fatalf("accepted invalid options: %+v", options)
		}
	}
	options, err := ValidateDNSOptions(DNSOptions{Servers: []string{"127.0.0.1", "127.0.0.1:53"}, Domains: []string{"LAB.Example.", "lab.example"}})
	if err != nil || len(options.Servers) != 1 || len(options.Domains) != 1 || options.Domains[0] != "lab.example" {
		t.Fatalf("normalization: %+v %v", options, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := LookupADSRVWithOptions(ctx, nil, DNSOptions{}); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
	// A server that never replies must still stop promptly on cancellation.
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, _, err := LookupADSRVWithOptions(ctx, nil, DNSOptions{Servers: []string{conn.LocalAddr().String()}, Domains: []string{"lab.example"}}); err != context.DeadlineExceeded {
		t.Fatalf("deadline lost: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("DNS cancellation delayed")
	}
}
