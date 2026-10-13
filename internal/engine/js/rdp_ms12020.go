package js

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// CheckMS12020 tests the MCS user/channel ownership check used by Nmap's
// rdp-vuln-ms12-020 and Rapid7's ms12_020_check. A successful cross-user join
// is followed by the owner's valid join before disconnecting (no DoS action).
// Transport and protocol errors are inconclusive, never a patched result.
func CheckMS12020(ctx context.Context, host string, port int, timeout time.Duration) (bool, error) {
	w, protocol, close, err := openRDPWire(ctx, host, port, timeout, 0)
	if errors.Is(err, errRDPTLSRequired) {
		w, protocol, close, err = openRDPWire(ctx, host, port, timeout, 1)
	}
	if err != nil {
		return false, err
	}
	defer close()
	// Empty GCC userData from old sample probes is rejected by stricter RDP
	// implementations. Complete the ordinary MCS/GCC handshake first; this
	// check needs two MCS users and no MS_T120 or other static channel.
	if err = w.send(rdpConnectInitial(protocol, nil, 32)); err != nil {
		return false, err
	}
	response, err := w.mcsFrame(0x7f)
	if err != nil {
		return false, fmt.Errorf("MS12-020 connect response: %w", err)
	}
	if len(response) < 9 || response[8] != 0x66 {
		return false, fmt.Errorf("MS12-020 invalid MCS connect response")
	}
	if err = w.send(rdpTPDU([]byte{4, 1, 0, 1, 0})); err != nil {
		return false, err
	}
	users := make([]uint16, 2)
	for i := range users {
		if err = w.send(rdpTPDU([]byte{0x28})); err != nil {
			return false, err
		}
		p, readErr := w.mcsFrame(0x2e)
		if readErr != nil {
			return false, fmt.Errorf("MS12-020 attach user: %w", readErr)
		}
		if len(p) != 11 || p[8] != 0 {
			return false, fmt.Errorf("MS12-020 invalid attach user confirm")
		}
		users[i] = binary.BigEndian.Uint16(p[9:11])
	}
	if users[0] == users[1] || users[1] > 64534 {
		return false, fmt.Errorf("MS12-020 invalid user IDs")
	}
	channel := users[1] + 1001
	if err = w.send(rdpJoinRequest(users[0], channel)); err != nil {
		return false, err
	}
	p, err := w.mcsFrame(0x3e)
	if err != nil {
		return false, fmt.Errorf("MS12-020 channel join: %w", err)
	}
	if len(p) < 13 || binary.BigEndian.Uint16(p[9:11]) != users[0] || binary.BigEndian.Uint16(p[11:13]) != channel {
		return false, fmt.Errorf("MS12-020 invalid channel join confirm")
	}
	if p[8] == 0 {
		if len(p) != 15 || binary.BigEndian.Uint16(p[13:]) != channel {
			return false, fmt.Errorf("MS12-020 invalid joined channel")
		}
		// Finish the channel join with its rightful owner, even when the
		// vulnerability has already been established.
		if err = w.send(rdpJoinRequest(users[1], channel)); err != nil {
			return true, fmt.Errorf("MS12-020 detected; cleanup join failed: %w", err)
		}
		cleanup, err := w.mcsFrame(0x3e)
		if err != nil {
			return true, fmt.Errorf("MS12-020 detected; cleanup confirm: %w", err)
		}
		if len(cleanup) != 15 || cleanup[8] != 0 || binary.BigEndian.Uint16(cleanup[9:]) != users[1] || binary.BigEndian.Uint16(cleanup[11:]) != channel || binary.BigEndian.Uint16(cleanup[13:]) != channel {
			return true, fmt.Errorf("MS12-020 detected; invalid cleanup confirm")
		}
		return true, nil
	}
	if p[8] == 3 || p[8] == 6 {
		return false, nil
	} // rt-no-such-channel: ownership enforced.
	return false, fmt.Errorf("MS12-020 inconclusive join result %d", p[8])
}
