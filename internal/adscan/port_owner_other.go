//go:build !linux

package adscan

import (
	"context"
	"fmt"
	"runtime"
)

// Never terminate a system SMB service to acquire the receiver's port.
// A free port can be used on every platform; automatic owner management is
// currently Linux-only. Surface the bind error before opening a stop dialog.
func CheckCoercionPort(ip string) ([]PortOwner, error) {
	if err := probeCoercionPort(ip); err != nil {
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("не удалось открыть %s:445: %w; порт может занимать служба Windows SMB. Используй отдельный приёмник со свободным TCP/445; автоматическая остановка служб Windows не поддерживается", ip, err)
		}
		return nil, fmt.Errorf("не удалось открыть %s:445: %w; освободи порт вручную", ip, err)
	}
	return nil, nil
}

func StopCoercionPortOwners(ctx context.Context, ip string, _ []PortOwner) (*PortLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := CheckCoercionPort(ip); err != nil {
		return nil, err
	}
	return &PortLease{}, nil
}
func (l *PortLease) Restore() error { return nil }
func RestoreCoercionPorts() error   { return nil }
