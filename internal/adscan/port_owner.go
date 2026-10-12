package adscan

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
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

var portLeases = struct {
	sync.Mutex
	active map[*PortLease]bool
}{active: map[*PortLease]bool{}}

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
func CheckCoercionPort(ip string) ([]PortOwner, error) {
	if err := probeCoercionPort(ip); err == nil {
		return nil, nil
	} else if !errors.Is(err, syscall.EADDRINUSE) {
		return nil, err
	}
	inodes := map[string]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for inode := range listeningInodes(data, net.ParseIP(ip)) {
			inodes[inode] = true
		}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	owners := []PortOwner{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fds, _ := os.ReadDir(filepath.Join("/proc", entry.Name(), "fd"))
		found := false
		for _, fd := range fds {
			link, _ := os.Readlink(filepath.Join("/proc", entry.Name(), "fd", fd.Name()))
			if strings.HasPrefix(link, "socket:[") && inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] {
				found = true
				break
			}
		}
		if found {
			owner, err := readPortProcess(pid)
			if err == nil {
				owners = append(owners, owner)
			}
		}
	}
	sambaPID := 0
	for _, owner := range owners {
		if strings.HasPrefix(owner.Name, "smbd") {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			output, _ := exec.CommandContext(ctx, "systemctl", "show", "smbd", "--property=MainPID", "--value").Output()
			cancel()
			sambaPID, _ = strconv.Atoi(strings.TrimSpace(string(output)))
			break
		}
	}
	for i := range owners {
		if sambaPID > 0 {
			cgroup, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", owners[i].PID))
			if owners[i].PID == sambaPID || strings.Contains(string(cgroup), "/smbd.service") {
				owners[i].Service = "smbd"
			}
		}
	}
	if len(owners) == 0 {
		return nil, fmt.Errorf("TCP/445 занят, но владелец недоступен; запусти через start.sh от root")
	}
	return owners, nil
}
func listeningInodes(data []byte, ip net.IP) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != "0A" {
			continue
		}
		parts := strings.Split(f[1], ":")
		if len(parts) != 2 || parts[1] != "01BD" {
			continue
		}
		raw, err := hex.DecodeString(parts[0])
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			continue
		}
		for off := 0; off < len(raw); off += 4 {
			raw[off], raw[off+3] = raw[off+3], raw[off]
			raw[off+1], raw[off+2] = raw[off+2], raw[off+1]
		}
		address := net.IP(raw)
		if address.IsUnspecified() || address.Equal(ip) {
			out[f[9]] = true
		}
	}
	return out
}
func readPortProcess(pid int) (PortOwner, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return PortOwner{}, err
	}
	s := string(data)
	first, last := strings.Index(s, "("), strings.LastIndex(s, ")")
	if first < 0 || last <= first {
		return PortOwner{}, fmt.Errorf("invalid process stat")
	}
	fields := strings.Fields(s[last+1:])
	if len(fields) < 20 {
		return PortOwner{}, fmt.Errorf("incomplete process stat")
	}
	return PortOwner{PID: pid, Name: s[first+1 : last], StartTime: fields[19]}, nil
}

// Stop only confirmed owners still listening on the selected address. Samba is
// stopped through systemd and restored by the returned lease; other processes
// receive SIGTERM, with no automatic SIGKILL or restart.
func StopCoercionPortOwners(ctx context.Context, ip string, confirmed []PortOwner) (*PortLease, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	current, err := CheckCoercionPort(ip)
	if err != nil {
		return nil, err
	}
	if len(current) == 0 {
		return &PortLease{}, nil
	}
	for _, owner := range current {
		if owner.PID <= 1 || owner.PID == os.Getpid() || owner.PID == os.Getppid() {
			return nil, fmt.Errorf("порт использует этот процесс или защищённый PID; останови его обычным способом")
		}
		matched := false
		for _, old := range confirmed {
			if owner.PID == old.PID && owner.StartTime == old.StartTime {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("владелец порта изменился; повтори запуск и подтверди нового владельца")
		}
	}
	lease := &PortLease{ip: ip}
	for _, owner := range current {
		if owner.Service == "smbd" {
			lease.samba = true
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if lease.samba {
		portLeases.Lock()
		portLeases.active[lease] = true
		portLeases.Unlock()
		stopCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = exec.CommandContext(stopCtx, "systemctl", "stop", "smbd").Run()
		cancel()
		if err != nil {
			_ = lease.Restore()
			return nil, fmt.Errorf("остановка Samba: %w", err)
		}
	}
	for _, owner := range current {
		if ctx.Err() != nil {
			_ = lease.Restore()
			return nil, ctx.Err()
		}
		actual, e := readPortProcess(owner.PID)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil || actual.StartTime != owner.StartTime {
			_ = lease.Restore()
			return nil, fmt.Errorf("PID %d изменился; остановка отменена", owner.PID)
		}
		process, e := os.FindProcess(owner.PID)
		if e == nil {
			e = process.Signal(syscall.SIGTERM)
		}
		if e != nil && !errors.Is(e, syscall.ESRCH) {
			_ = lease.Restore()
			return nil, e
		}
	}
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err = waitCoercionPort(waitCtx, ip); err != nil {
		_ = lease.Restore()
		return nil, fmt.Errorf("порт не освободился: %w", err)
	}
	return lease, nil
}
func waitCoercionPort(ctx context.Context, ip string) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := probeCoercionPort(ip); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (l *PortLease) Restore() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.restored {
		return l.err
	}
	l.restored = true
	if l.samba {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = waitCoercionPort(ctx, l.ip)
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		l.err = exec.CommandContext(ctx, "systemctl", "start", "smbd").Run()
		cancel()
		portLeases.Lock()
		delete(portLeases.active, l)
		portLeases.Unlock()
	}
	return l.err
}
func RestoreCoercionPorts() error {
	portLeases.Lock()
	leases := []*PortLease{}
	for lease := range portLeases.active {
		leases = append(leases, lease)
	}
	portLeases.Unlock()
	var result error
	for _, lease := range leases {
		result = errors.Join(result, lease.Restore())
	}
	return result
}
