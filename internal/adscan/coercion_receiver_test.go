package adscan

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"github.com/hirochachacha/go-smb2"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/ntlm"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCoercionReceiverHandshake(t *testing.T) {
	ctx := context.Background()
	server, client := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	r := &coercionReceiver{events: map[string][]coercionEvent{}}
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); r.serve(ctx, server, "192.0.2.10") }()
	request := func(command uint16, session uint64, body []byte) []byte {
		b := smbResponse(nil, command, 0, session, body)
		le.PutUint32(b[16:], 0)
		return b
	}
	send := func(b []byte) []byte {
		t.Helper()
		if e := smbWrite(client, b); e != nil {
			t.Fatal(e)
		}
		response, e := smbRead(client)
		if e != nil {
			t.Fatal(e)
		}
		return response
	}
	body := make([]byte, 38)
	le.PutUint16(body, 36)
	le.PutUint16(body[2:], 1)
	le.PutUint16(body[4:], 1)
	le.PutUint16(body[36:], 0x210)
	response := send(request(0, 0, body))
	if le.Uint16(response[68:]) != 0x210 {
		t.Fatal("wrong dialect")
	}
	a := ntlm.Authentifier{Config: ntlm.NewConfig()}
	a.Config.Credential = credential.NewFromPassword("LAB\\audit", "offline-example-password")
	negotiate, e := a.Negotiate(ctx)
	if e != nil {
		t.Fatal(e)
	}
	setup := func(token []byte, session uint64) []byte {
		body := make([]byte, 24)
		le.PutUint16(body, 25)
		le.PutUint16(body[12:], 88)
		le.PutUint16(body[14:], uint16(len(token)))
		return request(1, session, append(body, token...))
	}
	response = send(setup(negotiate, 0))
	if le.Uint32(response[8:]) != 0xc0000016 {
		t.Fatal("expected challenge")
	}
	index := bytes.Index(response, []byte("NTLMSSP\x00"))
	if index < 0 {
		t.Fatal("missing challenge")
	}
	authenticate, e := a.Authenticate(ctx, response[index:])
	if e != nil {
		t.Fatal(e)
	}
	response = send(setup(authenticate, le.Uint64(response[40:])))
	if le.Uint32(response[8:]) != 0xc000006d {
		t.Fatal("receiver must not accept session")
	}
	<-done
	events := r.since("192.0.2.10", time.Time{})
	if len(events) != 3 || events[2].Stage != "ntlm-authenticate" || !strings.Contains(events[2].Identity, "audit") {
		t.Fatalf("unexpected events: %+v", events)
	}
	if strings.Contains(events[2].Identity, "offline-example-password") {
		t.Fatal("secret leaked")
	}
}
func TestNTLMIdentityRejectsInvalidBuffers(t *testing.T) {
	token := make([]byte, 64)
	copy(token, []byte("NTLMSSP\x00"))
	le.PutUint32(token[8:], 3)
	le.PutUint16(token[20:], 24)
	le.PutUint32(token[24:], 0xfffffff0)
	if _, e := ntlmIdentity(token); e == nil {
		t.Fatal("out-of-bounds buffer accepted")
	}
	token = make([]byte, 64)
	if _, e := ntlmIdentity(token); e == nil {
		t.Fatal("anonymous response accepted")
	}
}
func TestCoercionRejectsInvalidCallbackBeforeListening(t *testing.T) {
	for _, address := range []string{"", "0.0.0.0", "224.0.0.1", "example.invalid", "::1"} {
		if _, e := RunCoercion(context.Background(), CoercionOptions{Targets: []string{"192.0.2.1"}, Callback: address}, nil); e == nil {
			t.Fatalf("accepted %q", address)
		}
	}
}

func TestCoercionReceiverSMBClient(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := &coercionReceiver{events: map[string][]coercionEvent{}}
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); r.serve(ctx, server, "192.0.2.20") }()
	dialer := smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: "audit", Password: "offline-password", Domain: "LAB"}}
	_, err := dialer.DialContext(ctx, client)
	if err == nil {
		t.Fatal("receiver accepted login")
	}
	client.Close()
	<-done
	events := r.since("192.0.2.20", time.Time{})
	found := false
	for _, e := range events {
		if e.Stage == "ntlm-authenticate" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no authentication observed: %v; events: %+v", err, events)
	}
}

func TestCoercionSkipsLocalReceiver(t *testing.T) {
	reports, err := RunCoercion(context.Background(), CoercionOptions{Targets: []string{"127.0.0.1"}, Callback: "127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || len(reports[0].Checks) != 1 || reports[0].Checks[0].State != "skipped" {
		t.Fatalf("unexpected report: %+v", reports)
	}
}

func TestCoercionReusesScopedResponder(t *testing.T) {
	r := &coercionReceiver{allowed: map[string]bool{"192.0.2.10": true}}
	responderSessions.Lock()
	responderSessions.receivers["192.0.2.16"] = r
	responderSessions.Unlock()
	defer func() {
		responderSessions.Lock()
		delete(responderSessions.receivers, "192.0.2.16")
		responderSessions.Unlock()
	}()
	got, owned, err := receiverForCoercion(context.Background(), "192.0.2.16", map[string]bool{"192.0.2.10": true})
	if err != nil || owned || got != r {
		t.Fatalf("receiver not reused: %v %v", owned, err)
	}
	_, _, err = receiverForCoercion(context.Background(), "192.0.2.16", map[string]bool{"192.0.2.11": true})
	if err == nil {
		t.Fatal("receiver scope expanded silently")
	}
}

func TestSPNEGONegotiateLengths(t *testing.T) {
	token := spnegoNegotiate()
	var application asn1.RawValue
	rest, err := asn1.Unmarshal(token, &application)
	if err != nil || len(rest) != 0 || application.Class != 1 || application.Tag != 0 {
		t.Fatalf("invalid GSS application: %v", err)
	}
	var oid asn1.ObjectIdentifier
	rest, err = asn1.Unmarshal(application.Bytes, &oid)
	if err != nil || !oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}) {
		t.Fatal("wrong GSS OID")
	}
	var choice, sequence, mechContext, mechs asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &choice)
	if err != nil || len(rest) != 0 {
		t.Fatal("invalid NegTokenInit choice")
	}
	rest, err = asn1.Unmarshal(choice.Bytes, &sequence)
	if err != nil || len(rest) != 0 {
		t.Fatal("invalid NegTokenInit sequence")
	}
	rest, err = asn1.Unmarshal(sequence.Bytes, &mechContext)
	if err != nil || len(rest) != 0 {
		t.Fatal("invalid mechTypes context")
	}
	rest, err = asn1.Unmarshal(mechContext.Bytes, &mechs)
	if err != nil || len(rest) != 0 {
		t.Fatal("invalid mechTypes sequence")
	}
	rest, err = asn1.Unmarshal(mechs.Bytes, &oid)
	if err != nil || len(rest) != 0 || !oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}) {
		t.Fatal("invalid NTLM mechanism OID")
	}
}

func TestCoercionChallengeForIntegrityClient(t *testing.T) {
	ctx := context.Background()
	client := ntlm.Authentifier{Config: ntlm.NewConfig()}
	client.Config.Integrity = true
	client.Config.Credential = credential.NewFromPassword("LAB\\audit", "offline-example-password")
	negotiate, err := client.Negotiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ntlmChallenge(ctx, negotiate)
	if err != nil {
		t.Fatal(err)
	}
	challenge := &ntlm.ChallengeMessage{}
	if err := challenge.Unmarshal(ctx, token); err != nil {
		t.Fatal(err)
	}
	for _, attr := range []ntlm.AttrValueID{ntlm.AttrNetBIOSComputerName, ntlm.AttrNetBIOSDomainName} {
		if challenge.TargetInfo[attr] == nil {
			t.Fatalf("missing mandatory NetBIOS AV pair: %v", attr)
		}
	}
	if !challenge.Negotiate.IsSet(ntlm.TargetTypeServer) || challenge.Negotiate.IsSet(ntlm.TargetTypeDomain) {
		t.Fatal("standalone receiver must keep server target type")
	}
	if _, err := client.Authenticate(ctx, token); err != nil {
		t.Fatalf("integrity client rejected challenge: %v", err)
	}
}

func TestNTLMAnonymousIsNotCredentialEvidence(t *testing.T) {
	token := make([]byte, 64)
	copy(token, []byte("NTLMSSP\x00"))
	le.PutUint32(token[8:], 3)
	if _, err := ntlmIdentity(token); !errors.Is(err, errAnonymousNTLM) {
		t.Fatalf("anonymous response: %v", err)
	}
	le.PutUint16(token[20:], 1)
	le.PutUint32(token[24:], 63)
	if _, err := ntlmIdentity(token); err == nil || errors.Is(err, errAnonymousNTLM) {
		t.Fatalf("malformed response must not be anonymous: %v", err)
	}
}
