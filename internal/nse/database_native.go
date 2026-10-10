package nse

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"wscan/internal/domain"

	"wscan/internal/engine/js"
)

func nativeDatabaseScript(id string) bool {
	switch id {
	case "pgsql-brute", "mysql-brute", "ms-sql-brute", "redis-brute", "mysql-empty-password", "ms-sql-empty-password":
		return true
	}
	return false
}
func databaseRejected(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, message := range []string{"access denied for user", "password authentication failed", "login failed for user", "wrongpass", "invalid password", "noauth", "empty password returned by client"} {
		if strings.Contains(s, message) {
			return true
		}
	}
	return false
}
func (r *Runner) runDatabaseCredentials(ctx context.Context, id string, host HostInfo, ports []PortInfo) ([]ScriptResult, bool, error) {
	family, standard := "", 0
	switch id {
	case "pgsql-brute":
		family, standard = "postgresql", 5432
	case "mysql-brute", "mysql-empty-password":
		family, standard = "mysql", 3306
	case "ms-sql-brute", "ms-sql-empty-password":
		family, standard = "mssql", 1433
	case "redis-brute":
		family, standard = "redis", 6379
	}
	if r.cfg.Args["brute.credfile"] != "" {
		return nil, false, fmt.Errorf("native database brute: use userdb/passdb instead of brute.credfile")
	}
	max := 3
	if s := r.cfg.Args["brute.guesses"]; s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 100 {
			return nil, false, fmt.Errorf("brute.guesses must be 1..100")
		}
		max = n
	}
	delay := time.Duration(0)
	if s := r.cfg.Args["brute.delay"]; s != "" {
		n, e := strconv.ParseFloat(s, 64)
		if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 3600 {
			return nil, false, fmt.Errorf("invalid brute.delay")
		}
		delay = time.Duration(n * float64(time.Second))
	}
	empty := strings.HasSuffix(id, "empty-password")
	var results []ScriptResult
	var errs []error
	ran := false
	ctrl := newControl(ctx, r.cfg)
	defer ctrl.close()
	if r.cfg.SelectedServicesOnly {
		ctrl.bindScope(host, ports)
	}
	for _, p := range ports {
		if (p.Protocol != "" && p.Protocol != "tcp") || (p.State != "" && p.State != "open") {
			continue
		}
		name := strings.ToLower(p.Service)
		if actual := domain.DatabaseFamily(name); actual != "" && actual != domain.DatabaseFamily(family) {
			continue
		}
		if p.Number != standard && name != family && !(family == "postgresql" && name == "pgsql") && !(family == "mssql" && (name == "ms-sql-s" || name == "ms-sql")) {
			continue
		}
		ran = true
		if p.Tunnel == "ssl" || p.Tunnel == "tls" {
			errs = append(errs, fmt.Errorf("%s: TLS-only service requires a TLS-aware credential client", id))
			continue
		}
		users := []string{""}
		passwords := []string{""}
		if empty {
			if family == "mysql" {
				users = []string{"", "root"}
			} else {
				users = []string{"sa"}
			}
		} else {
			if family != "redis" {
				file := r.cfg.Args["userdb"]
				if file == "" {
					file = filepath.Join(r.libraryDir, "nmap", "nselib", "data", "usernames.lst")
				}
				var err error
				users, err = telnetDictionary(file, 10000)
				if err != nil {
					return results, ran, err
				}
			}
			file := r.cfg.Args["passdb"]
			if file == "" {
				file = filepath.Join(r.libraryDir, "nmap", "nselib", "data", "passwords.lst")
			}
			var err error
			passwords, err = telnetDictionary(file, 100000)
			if err != nil {
				return results, ran, err
			}
		}
		timeout := r.cfg.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		counts := map[string]int{}
		done := map[string]bool{}
		seen := map[string]bool{}
		attempts := 0
		var accounts []string
		try := func(user, pass string) error {
			key := user + "\x00" + pass
			if done[user] || seen[key] || counts[user] >= max {
				return nil
			}
			seen[key] = true
			if attempts > 0 && delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
			if err := ctrl.checkScope("tcp", net.JoinHostPort(host.IP, strconv.Itoa(p.Number))); err != nil {
				return err
			}
			if err := ctrl.wait(); err != nil {
				return err
			}
			counts[user]++
			attempts++
			var ok bool
			var err error
			switch family {
			case "postgresql":
				ok, err = js.NewPGClient(ctx, timeout).ConnectWithPassword(host.IP, p.Number, user, pass)
			case "mysql":
				ok, err = js.NewMySQLClient(ctx, timeout).Connect(host.IP, p.Number, user, pass)
			case "mssql":
				ok, err = js.NewMSSQLClient(ctx, timeout).Connect(host.IP, p.Number, user, pass)
			case "redis":
				ok, err = js.CheckRedisPassword(ctx, host.IP, p.Number, pass, timeout)
			}
			if err != nil && !databaseRejected(err) {
				return err
			}
			if ok {
				done[user] = true
				label := user
				if label == "" {
					label = "(anonymous/password-only)"
				}
				kind := "valid password"
				if pass == "" {
					kind = "empty password / no-password access"
				}
				accounts = append(accounts, fmt.Sprintf("%s: %s (secret omitted)", label, kind))
			}
			return nil
		}
		var err error
		if !empty && family != "redis" && r.cfg.Args["brute.useraspass"] != "false" {
			for _, u := range users {
				if err = try(u, u); err != nil {
					break
				}
			}
		}
		if err == nil && !empty && family != "redis" && r.cfg.Args["brute.emptypass"] == "true" {
			for _, u := range users {
				if err = try(u, ""); err != nil {
					break
				}
			}
		}
		if err == nil {
		outer:
			for _, pass := range passwords {
				pending := false
				for _, u := range users {
					if !done[u] && counts[u] < max {
						pending = true
					}
					if err = try(u, pass); err != nil {
						break outer
					}
				}
				if !pending {
					break
				}
			}
		}
		if len(accounts) > 0 {
			results = append(results, ScriptResult{ScriptID: id, Port: p.Number, Output: "Accounts\n  " + strings.Join(accounts, "\n  ") + fmt.Sprintf("\nPerformed %d guesses; limit %d per username", attempts, max)})
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %d/tcp: %w", id, p.Number, err))
		}
	}
	return results, ran, errors.Join(errs...)
}
