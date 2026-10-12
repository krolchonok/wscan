package adscan

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/oiweiwei/go-msrpc/ssp/ntlm"
)

func TestResponderEmptyAuthenticateLifecycle(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	r := &coercionReceiver{debug: true, events: map[string][]coercionEvent{}}
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); r.serve(context.Background(), server, "192.0.2.10") }()
	request := func(command uint16, session uint64, body []byte) []byte {
		b := smbResponse(nil, command, 0, session, body)
		le.PutUint32(b[16:], 0)
		return b
	}
	send := func(b []byte) []byte {
		t.Helper()
		if err := smbWrite(client, b); err != nil {
			t.Fatal(err)
		}
		response, err := smbRead(client)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	body := make([]byte, 38)
	le.PutUint16(body, 36)
	le.PutUint16(body[2:], 1)
	le.PutUint16(body[36:], 0x210)
	send(request(0, 0, body))
	a := ntlm.Authentifier{Config: ntlm.NewConfig()}
	negotiate, err := a.Negotiate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	setup := func(token []byte, session uint64) []byte {
		body := make([]byte, 24)
		le.PutUint16(body, 25)
		le.PutUint16(body[12:], 88)
		le.PutUint16(body[14:], uint16(len(token)))
		return request(1, session, append(body, token...))
	}
	response := send(setup(negotiate, 0))
	if le.Uint32(response[8:]) != 0xc0000016 {
		t.Fatal("challenge status changed")
	}
	authenticate := make([]byte, 64)
	copy(authenticate, "NTLMSSP\x00")
	le.PutUint32(authenticate[8:], 3)
	response = send(setup(authenticate, le.Uint64(response[40:])))
	if le.Uint32(response[8:]) != 0xc000006d {
		t.Fatal("authentication response changed")
	}
	<-done
	events := r.diagnosticHistory("192.0.2.10")
	expected := []string{"CONNECTED", "NEGOTIATE_REQUEST", "NEGOTIATE_RESPONSE", "SESSION_SETUP", "NTLM_MESSAGE", "NTLM_NEGOTIATE", "CHALLENGE_SENT", "SESSION_SETUP", "NTLM_MESSAGE", "AUTH_RECEIVED", "USER_EMPTY", "DOMAIN_EMPTY", "EMPTY_NTLM_RESPONSE", "ANONYMOUS_AUTH_ATTEMPT", "AUTH_FAILED", "SESSION_CLOSED"}
	if len(events) != len(expected) {
		t.Fatalf("events %+v", events)
	}
	for i, event := range events {
		if event.Stage != expected[i] || event.ConnectionID != events[0].ConnectionID || event.Time.Before(events[0].Time) {
			t.Fatalf("event %d: %+v", i, event)
		}
		if event.Stage == "AUTH_SUCCESS" || event.Stage == "ANONYMOUS_AUTH" {
			t.Fatal("rejected session classified as successful")
		}
		if event.Stage == "AUTH_RECEIVED" {
			if event.NTLMType != 3 || event.UserLength == nil || *event.UserLength != 0 || event.DomainLength == nil || *event.DomainLength != 0 || event.ResponseLength == nil || *event.ResponseLength != 0 {
				t.Fatal(event)
			}
		}
	}
	last := events[len(events)-1]
	if last.LastState != "AUTH_FAILED" || last.Reason != "SERVER_REJECTED_AUTH" {
		t.Fatal(last)
	}
}

func TestResponderDiagnosticDoesNotStopAtHistoryLimit(t *testing.T) {
	observed := 0
	r := &coercionReceiver{debug: true, observeDiagnostic: func(SMBDiagnostic) { observed++ }}
	for i := 0; i < 600; i++ {
		r.diagnostic("192.0.2.10", SMBDiagnostic{ConnectionID: uint64(i + 1), Stage: "CONNECTED"})
	}
	history := r.diagnosticHistory("192.0.2.10")
	if observed != 600 || len(history) != 256 || history[0].ConnectionID != 345 || history[255].ConnectionID != 600 {
		t.Fatalf("observed=%d history=%d", observed, len(history))
	}
}
func TestResponderConcurrentConnectionsHaveUniqueIDs(t *testing.T) {
	r := &coercionReceiver{debug: true, events: map[string][]coercionEvent{}}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		server, client := net.Pipe()
		wg.Add(1)
		go func() { defer wg.Done(); defer server.Close(); r.serve(context.Background(), server, "192.0.2.10") }()
		client.Close()
	}
	wg.Wait()
	history := r.diagnosticHistory("192.0.2.10")
	ids := map[uint64][]string{}
	for _, event := range history {
		ids[event.ConnectionID] = append(ids[event.ConnectionID], event.Stage)
		if event.Stage == "SESSION_CLOSED" && event.Reason != "PEER_EOF" {
			t.Fatal(event)
		}
	}
	if len(ids) != 12 {
		t.Fatal(ids)
	}
	for _, events := range ids {
		if len(events) != 2 || events[0] != "CONNECTED" || events[1] != "SESSION_CLOSED" {
			t.Fatal(events)
		}
	}
}
func TestResponderMalformedFrameAndUnknownIO(t *testing.T) {
	server, client := net.Pipe()
	r := &coercionReceiver{debug: true, events: map[string][]coercionEvent{}}
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); r.serve(context.Background(), server, "192.0.2.10") }()
	_, err := client.Write([]byte{0, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-done
	events := r.diagnosticHistory("192.0.2.10")
	if len(events) != 3 || events[1].Stage != "PROTOCOL_ERROR" || events[2].Reason != "INVALID_SMB_FRAME" {
		t.Fatal(events)
	}
	cases := []struct {
		err           error
		stage, reason string
	}{{io.EOF, "", "PEER_EOF"}, {io.ErrUnexpectedEOF, "PROTOCOL_ERROR", "TRUNCATED_FRAME"}, {syscall.ECONNRESET, "CONNECTION_RESET", "PEER_RESET"}, {errors.New("opaque failure with private payload"), "", "UNKNOWN"}}
	for _, tc := range cases {
		stage, reason := smbIOReason(context.Background(), tc.err)
		if stage != tc.stage || reason != tc.reason {
			t.Fatalf("got %s %s", stage, reason)
		}
	}
}

type shortSMBDeadline struct{ net.Conn }

func (c shortSMBDeadline) SetDeadline(time.Time) error {
	return c.Conn.SetDeadline(time.Now().Add(25 * time.Millisecond))
}
func TestResponderTimeoutHasLastState(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	r := &coercionReceiver{debug: true, events: map[string][]coercionEvent{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		r.serve(context.Background(), shortSMBDeadline{server}, "192.0.2.10")
	}()
	<-done
	events := r.diagnosticHistory("192.0.2.10")
	if len(events) != 3 || events[1].Stage != "CONNECTION_TIMEOUT" || events[2].LastState != "CONNECTED" || events[2].Reason != "IO_TIMEOUT" {
		t.Fatal(events)
	}
}
func TestResponderDiagnosticFormatAndDefaultVerbosity(t *testing.T) {
	zero := 0
	status := uint32(0xc000006d)
	d := SMBDiagnostic{Time: time.Now(), ConnectionID: 1, Remote: "192.0.2.10:54321", Stage: "AUTH_RECEIVED", LastState: "CHALLENGE_SENT", Dialect: 0x210, NTLMType: 3, DomainLength: &zero, UserLength: &zero, ResponseLength: &zero, Status: &status}
	s := d.String()
	for _, want := range []string{"peer=192.0.2.10:54321", "conn=1", "ntlm_type=3", "user_length=0 present=false", "ntstatus=0xC000006D(STATUS_LOGON_FAILURE)"} {
		if !strings.Contains(s, want) {
			t.Fatal(s)
		}
	}
	if smbStatusName(0xdeadbeef) != "UNKNOWN" {
		t.Fatal("invented status")
	}
	r := &coercionReceiver{}
	r.diagnostic("host", SMBDiagnostic{Stage: "NTLM_NEGOTIATE"})
	r.diagnostic("host", SMBDiagnostic{Stage: "CONNECTED"})
	if events := r.diagnosticHistory("host"); len(events) != 1 || events[0].Stage != "CONNECTED" {
		t.Fatal(events)
	}
}
