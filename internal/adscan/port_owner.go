package adscan

import (
	"fmt"
	"net"
	"sync"
)

type PortOwner struct {
	PID                      int
	Name, StartTime, Service string
}
type PortLease struct {
	mu       sync.Mutex
	restored bool
	ip       string
	samba    bool
	err      error
}

func probeCoercionPort(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil || parsed.IsUnspecified() || parsed.IsMulticast() {
		return fmt.Errorf("укажи локальный IPv4 приёмника")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(ip, "445"))
	if err == nil {
		listener.Close()
	}
	return err
}
