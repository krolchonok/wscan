package adscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var smbConnectionSequence atomic.Uint64

// SMBDiagnostic contains metadata only. It cannot hold NTLM payloads, names,
// workstation values, challenges, passwords or hashes.
type SMBDiagnostic struct {
	Time           time.Time `json:"time"`
	ConnectionID   uint64    `json:"connection_id"`
	Remote         string    `json:"remote"`
	Stage          string    `json:"stage"`
	LastState      string    `json:"last_state"`
	Dialect        uint16    `json:"dialect,omitempty"`
	NTLMType       uint32    `json:"ntlm_type,omitempty"`
	DomainLength   *int      `json:"domain_length,omitempty"`
	UserLength     *int      `json:"user_length,omitempty"`
	ResponseLength *int      `json:"ntlm_response_length,omitempty"`
	Status         *uint32   `json:"ntstatus,omitempty"`
	Reason         string    `json:"reason,omitempty"`
}

func (d SMBDiagnostic) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s [SMB] conn=%d peer=%s %s last=%s", d.Time.UTC().Format(time.RFC3339Nano), d.ConnectionID, d.Remote, d.Stage, d.LastState)
	if d.Dialect != 0 {
		fmt.Fprintf(&b, " dialect=0x%04X", d.Dialect)
	}
	if d.NTLMType != 0 {
		fmt.Fprintf(&b, " ntlm_type=%d", d.NTLMType)
	}
	for _, field := range []struct {
		name  string
		value *int
	}{{"domain_length", d.DomainLength}, {"user_length", d.UserLength}, {"ntlm_response_length", d.ResponseLength}} {
		if field.value != nil {
			fmt.Fprintf(&b, " %s=%d present=%t", field.name, *field.value, *field.value > 0)
		}
	}
	if d.Status != nil {
		fmt.Fprintf(&b, " ntstatus=0x%08X(%s)", *d.Status, smbStatusName(*d.Status))
	}
	if d.Reason != "" {
		fmt.Fprintf(&b, " reason=%s", d.Reason)
	}
	return b.String()
}
func smbStatusName(status uint32) string {
	switch status {
	case 0:
		return "STATUS_SUCCESS"
	case 0xc0000016:
		return "STATUS_MORE_PROCESSING_REQUIRED"
	case 0xc000006d:
		return "STATUS_LOGON_FAILURE"
	case 0xc0000022:
		return "STATUS_ACCESS_DENIED"
	default:
		return "UNKNOWN"
	}
}

type receiverDiagnostics struct {
	debug     bool
	observe   func(SMBDiagnostic)
	exportDir string
}

func (r *coercionReceiver) diagnostic(host string, d SMBDiagnostic) {
	if !r.debug && !smbBasicStage(d.Stage) {
		return
	}
	// Serialize observer calls, including simultaneous connections and admission
	// failures. Within a connection, serve emits synchronously in wire order.
	r.diagnosticMu.Lock()
	defer r.diagnosticMu.Unlock()
	r.mu.Lock()
	if r.diagnostics == nil {
		r.diagnostics = map[string][]SMBDiagnostic{}
	}
	if r.allowed == nil || r.allowed[host] {
		events := r.diagnostics[host]
		if len(events) >= 256 {
			copy(events, events[1:])
			events = events[:255]
		}
		r.diagnostics[host] = append(events, d)
	}
	observe := r.observeDiagnostic
	r.mu.Unlock()
	// Persistence/live output must continue when the bounded memory history fills.
	if observe != nil {
		observe(d)
	}
}
func smbBasicStage(stage string) bool {
	switch stage {
	case "CONNECTED", "CONNECTION_REJECTED", "AUTH_RECEIVED", "EMPTY_NTLM_RESPONSE", "ANONYMOUS_AUTH_ATTEMPT", "AUTH_FAILED", "AUTH_SUCCESS", "PROTOCOL_ERROR", "CONNECTION_RESET", "CONNECTION_TIMEOUT", "SESSION_CLOSED", "SERVER_ERROR":
		return true
	}
	return false
}
func (r *coercionReceiver) diagnosticHistory(host string) []SMBDiagnostic {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]SMBDiagnostic(nil), r.diagnostics[host]...)
}
func smbIOReason(ctx context.Context, err error) (stage, reason string) {
	if ctx.Err() != nil {
		return "", "SERVER_CANCELLED"
	}
	if errors.Is(err, io.EOF) {
		return "", "PEER_EOF"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "CONNECTION_RESET", "PEER_RESET"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "CONNECTION_TIMEOUT", "IO_TIMEOUT"
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "PROTOCOL_ERROR", "TRUNCATED_FRAME"
	}
	if err != nil && (err.Error() == "unsupported framing" || err.Error() == "invalid SMB length") {
		return "PROTOCOL_ERROR", "INVALID_SMB_FRAME"
	}
	return "", "UNKNOWN"
}
