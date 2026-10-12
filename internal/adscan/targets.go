package adscan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"wscan/internal/discovery"
)

// ValidateTargets accepts explicit addresses, DNS names and private IPv4 ranges.
func ValidateTargets(targets []string) error {
	if len(targets) == 0 {
		return fmt.Errorf("укажите IP, имя хоста или CIDR для AD-проверки")
	}
	for _, target := range targets {
		if strings.Contains(target, "/") {
			if _, err := ValidatePrivateSubnet(target); err != nil {
				return err
			}
		} else {
			if err := discovery.ValidateTarget(target); err != nil {
				return err
			}
			if strings.ContainsAny(target, ":/@") && net.ParseIP(target) == nil {
				return fmt.Errorf("AD-цель %q: укажите IP или имя хоста без URL и порта", target)
			}
		}
	}
	return nil
}

// ScanTargets never turns individual hosts into a containing subnet.
func ScanTargets(ctx context.Context, targets []string, progress func(int, int)) (Result, error) {
	if err := ValidateTargets(targets); err != nil {
		return Result{}, err
	}
	result := Result{CIDR: strings.Join(targets, " ")}
	seen := map[string]bool{}
	completed := 0
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		var ranges []string
		if strings.Contains(target, "/") {
			ranges = []string{target}
		} else {
			ips := []net.IPAddr{{IP: net.ParseIP(target)}}
			if ips[0].IP == nil {
				var err error
				ips, err = net.DefaultResolver.LookupIPAddr(ctx, target)
				if err != nil {
					return result, fmt.Errorf("AD: имя %s не разрешено: %w", target, err)
				}
			}
			for _, ip := range ips {
				ranges = append(ranges, ip.IP.String())
			}
		}
		for _, address := range ranges {
			if seen[address] {
				continue
			}
			seen[address] = true
			emit := func(done, total int) {
				if progress != nil {
					progress(completed+done, completed+total)
				}
			}
			var part Result
			var err error
			if strings.Contains(address, "/") {
				part, err = Scan(ctx, address, emit)
			} else {
				part, err = scanRange(ctx, address, net.ParseIP(address), 1, emit)
			}
			completed += part.HostsScanned * len(adPorts)
			result.HostsScanned += part.HostsScanned
			result.Hosts = append(result.Hosts, part.Hosts...)
			if err != nil {
				return result, err
			}
		}
	}
	// An overlapping range and explicit host must not duplicate downstream checks.
	unique := result.Hosts[:0]
	hosts := map[string]bool{}
	for _, host := range result.Hosts {
		if !hosts[host.Address] {
			hosts[host.Address] = true
			unique = append(unique, host)
		}
	}
	result.Hosts = unique
	return result, nil
}
