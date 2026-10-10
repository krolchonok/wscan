package nse

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wscan/internal/telnet"
)

func telnetDictionary(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 65536)
	var result []string
	seen := map[string]bool{}
	for scanner.Scan() {
		s := strings.TrimSuffix(scanner.Text(), "\r")
		if s == "" || strings.HasPrefix(s, "#!") || strings.HasPrefix(s, "#") {
			continue
		}
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
		if len(result) > limit {
			return nil, fmt.Errorf("Telnet: dictionary exceeds %d entries", limit)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("Telnet: empty dictionary %s", path)
	}
	return result, nil
}

// runTelnetBrute replaces only this script's unsupported Lua scheduler. Network
// access still uses the runner's scope/rate control; attempts are sequential.
func (r *Runner) runTelnetBrute(ctx context.Context, host HostInfo, ports []PortInfo) ([]ScriptResult, bool, error) {
	var eligible []PortInfo
	for _, p := range ports {
		if p.Protocol != "" && p.Protocol != "tcp" {
			continue
		}
		if p.State != "" && p.State != "open" {
			continue
		}
		if p.Number == 23 || p.Number == 992 || p.Service == "telnet" || p.Service == "telnets" {
			eligible = append(eligible, p)
		}
	}
	if len(eligible) == 0 {
		return nil, false, nil
	}
	args := r.cfg.Args
	max := 3
	if s := args["brute.guesses"]; s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 100 {
			return nil, true, fmt.Errorf("Telnet: brute.guesses must be 1..100")
		}
		max = n
	}
	delay := time.Duration(0)
	if s := args["brute.delay"]; s != "" {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 3600 {
			return nil, true, fmt.Errorf("Telnet: invalid brute.delay")
		}
		delay = time.Duration(f * float64(time.Second))
	}
	timeout := r.cfg.Timeout
	if s := args["telnet-brute.timeout"]; s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return nil, true, fmt.Errorf("Telnet: invalid timeout")
		}
		timeout = d
	}
	usersPath := args["userdb"]
	if usersPath == "" {
		usersPath = filepath.Join(r.libraryDir, "nmap", "nselib", "data", "usernames.lst")
	}
	passPath := args["passdb"]
	if passPath == "" {
		passPath = filepath.Join(r.libraryDir, "nmap", "nselib", "data", "passwords.lst")
	}
	users, err := telnetDictionary(usersPath, 10000)
	if err != nil {
		return nil, true, err
	}
	passwords, err := telnetDictionary(passPath, 100000)
	if err != nil {
		return nil, true, err
	}
	if args["brute.credfile"] != "" {
		return nil, true, fmt.Errorf("Telnet: brute.credfile unsupported; use userdb/passdb")
	}
	ctrl := newControl(ctx, r.cfg)
	defer ctrl.close()
	if r.cfg.SelectedServicesOnly {
		ctrl.bindScope(host, ports)
	}
	var results []ScriptResult
	var errs []error
	for _, p := range eligible {
		if p.Number == 992 || p.Service == "telnets" || p.Tunnel == "ssl" || p.Tunnel == "tls" {
			errs = append(errs, fmt.Errorf("Telnet: TLS listener unsupported on %d; no plaintext credentials sent", p.Number))
			continue
		}
		counts := map[string]int{}
		done := map[string]bool{}
		tried := map[string]bool{}
		attempts := 0
		var accounts []string
		try := func(user, pass, source string) error {
			key := user + "\x00" + pass
			if done[user] || counts[user] >= max || tried[key] {
				return nil
			}
			tried[key] = true
			if attempts > 0 && delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
			conn, err := ctrl.dial("tcp", net.JoinHostPort(host.IP, strconv.Itoa(p.Number)))
			if err != nil {
				return err
			}
			counts[user]++
			attempts++
			ok, err := telnet.Login(ctx, conn, timeout, user, pass)
			if err != nil {
				return err
			}
			if ok {
				done[user] = true
				accounts = append(accounts, fmt.Sprintf("%s: valid credential (%s; password omitted)", user, source))
			}
			return nil
		}
		portErr := error(nil)
		// Username-as-password is enabled by upstream by default and must precede
		// dictionary guesses: root/root is absent from the default password file.
		if args["brute.useraspass"] != "false" {
			for _, u := range users {
				if portErr = try(u, u, "username-as-password"); portErr != nil {
					break
				}
			}
		}
		if portErr == nil && args["brute.emptypass"] == "true" {
			for _, u := range users {
				if portErr = try(u, "", "empty password"); portErr != nil {
					break
				}
			}
		}
		if portErr == nil {
		outer:
			for _, pass := range passwords {
				pending := false
				for _, u := range users {
					if !done[u] && counts[u] < max {
						pending = true
					}
					if portErr = try(u, pass, "dictionary"); portErr != nil {
						break outer
					}
				}
				if !pending {
					break
				}
			}
		}
		if len(accounts) > 0 {
			results = append(results, ScriptResult{ScriptID: "telnet-brute", Port: p.Number, Output: "Accounts\n  " + strings.Join(accounts, "\n  ") + fmt.Sprintf("\nPerformed %d guesses; limit %d per username", attempts, max)})
		}
		if portErr != nil {
			errs = append(errs, fmt.Errorf("telnet-brute %d/tcp: %w", p.Number, portErr))
		}
	}
	return results, true, errors.Join(errs...)
}
