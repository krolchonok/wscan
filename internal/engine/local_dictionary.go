package engine

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
	"wscan/internal/discovery"
	"wscan/internal/domain"
)

// LocalDictionary streams passwords, retains bounded usernames, and stops
// each host/account after success, lockout or the configured failure limit.
// Password values are never included in progress or the stored AuthAttempt.
func (e *Engine) LocalDictionary(ctx context.Context, p domain.Project, targets []domain.Service, users []string, passwords io.Reader, o LocalSprayOptions, progress func(domain.AuthAttempt)) (*SprayResult, error) {
	if !p.AllowCredentialAttack {
		return nil, fmt.Errorf("credential attacks are disabled for this project")
	}
	if len(users) == 0 || len(users) > 5000 {
		return nil, fmt.Errorf("укажи 1–5000 локальных имён")
	}
	if passwords == nil {
		return nil, fmt.Errorf("словарь паролей не задан")
	}
	unique := []string{}
	seen := map[string]bool{}
	for _, u := range users {
		u = strings.TrimSpace(u)
		if u == "" || strings.ContainsAny(u, "\\/@\x00\r\n") {
			return nil, fmt.Errorf("пользователи задаются без домена")
		}
		if !seen[strings.ToLower(u)] {
			seen[strings.ToLower(u)] = true
			unique = append(unique, u)
		}
	}
	type identityResult struct {
		id  discovery.SMBIdentity
		err error
	}
	cache := map[string]identityResult{}
	discover := func(ctx context.Context, t domain.Service, timeout time.Duration) (discovery.SMBIdentity, error) {
		key := fmt.Sprintf("%s:%d", t.Host, t.Port)
		r, ok := cache[key]
		if !ok {
			r.id, r.err = e.discoverLocalMachine(ctx, p.ID, t, timeout)
			cache[key] = r
		}
		return r.id, r.err
	}
	stopped := map[string]bool{}
	var out SprayResult
	scanner := bufio.NewScanner(passwords)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return &out, err
		}
		sent := false
		for _, t := range targets {
			var creds []domain.Credential
			for _, u := range unique {
				if !stopped[localAttemptKey(t.Host, u)] {
					creds = append(creds, domain.Credential{Type: "password", Username: u, Secret: scanner.Text()})
				}
			}
			if len(creds) == 0 {
				continue
			}
			sent = true
			r, err := e.sprayLocalCredentials(ctx, p, []domain.Service{t}, creds, o, discover, tryLogin)
			if r != nil {
				for _, a := range r.Attempts {
					out.Attempts = append(out.Attempts, a)
					if progress != nil {
						progress(a)
					}
					if a.Success || a.Skipped || strings.Contains(strings.ToUpper(a.Error), "LOCKED") || strings.Contains(strings.ToUpper(a.Error), "0XC0000234") {
						stopped[localAttemptKey(a.Target, a.Username)] = true
					}
				}
			}
			if err != nil {
				return &out, err
			}
		}
		if !sent {
			break
		}
		// Each batch has a fresh pacing clock; also bound starts between passwords.
		timer := time.NewTimer(max(o.Delay, time.Second/time.Duration(max(1, e.config.RPS))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return &out, ctx.Err()
		case <-timer.C:
		}
	}
	return &out, scanner.Err()
}
