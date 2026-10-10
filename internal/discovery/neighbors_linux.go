//go:build linux

package discovery

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
	"time"
)

// TCP/ICMP traffic causes Linux to resolve directly connected neighbors with
// ARP. Read their confirmed state via netlink without requiring raw sockets.
// STALE, DELAY, INCOMPLETE, FAILED and static entries are not evidence of life.
func confirmedNeighborHosts(ctx context.Context, candidates []string, live map[string]bool) []string {
	pending := make(map[string]bool)
	for _, host := range candidates {
		if !live[host] {
			pending[host] = true
		}
	}
	if len(pending) == 0 {
		return nil
	}
	var found []string
	// A stale entry normally waits five seconds before the kernel reprobes it.
	// Wait only for neighbors with an outstanding resolution, never remote hosts.
	deadline := time.NewTimer(6 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		states, err := neighborStates()
		if err != nil {
			return found
		}
		resolving := false
		for host := range pending {
			state := states[host]
			if state == 0x02 { // NUD_REACHABLE: recent positive feedback.
				found = append(found, host)
				delete(pending, host)
			} else if state&(0x01|0x08|0x10) != 0 { // INCOMPLETE, DELAY, PROBE.
				resolving = true
			}
		}
		if !resolving {
			return found
		}
		select {
		case <-ctx.Done():
			return found
		case <-deadline.C:
			return found
		case <-ticker.C:
		}
	}
	return found
}

func neighborStates() (map[string]uint16, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_INET)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	states := make(map[string]uint16)
	for _, message := range messages {
		data := message.Data
		if message.Header.Type != syscall.RTM_NEWNEIGH || len(data) < 12 || data[0] != syscall.AF_INET {
			continue
		}
		state := binary.NativeEndian.Uint16(data[8:10])
		// ndmsg is 12 bytes, followed by aligned rtattr records.
		for attrs := data[12:]; len(attrs) >= 4; {
			length := int(binary.NativeEndian.Uint16(attrs[:2]))
			kind := binary.NativeEndian.Uint16(attrs[2:4]) & 0x3fff
			if length < 4 || length > len(attrs) {
				break
			}
			if kind == 1 && length == 8 { // NDA_DST, IPv4 address.
				host := net.IP(attrs[4:8]).String()
				states[host] |= state
			}
			aligned := (length + 3) &^ 3
			if aligned > len(attrs) {
				break
			}
			attrs = attrs[aligned:]
		}
	}
	return states, nil
}
