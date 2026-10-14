package engine

import (
	"context"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"wscan/internal/discovery"
	"wscan/internal/domain"
	js "wscan/internal/engine/js"
	"wscan/internal/nse"
)

type LocalSprayOptions struct {
	// Policies must be local policies read from the exact target; domain PSOs
	// cannot be substituted for its local SAM policy.
	Policies map[string]domain.PasswordPolicy
	Delay    time.Duration
}

type cachedLocalPolicy struct {
	policy domain.PasswordPolicy
	at     time.Time
}

type localPolicyCache struct {
	mu       sync.Mutex
	policies map[string]cachedLocalPolicy
}

// RememberLocalPolicy accepts only a policy read from the target's local SAM.
// Cache lifetime is short; even a fresh policy cannot account for other clients.
func (e *Engine) RememberLocalPolicy(projectID int64, p domain.PasswordPolicy) {
	if p.Source != "local" || p.DN == "" || p.LockoutThreshold == nil {
		return
	}
	cache := e.localPolicyCache
	if cache == nil {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.policies == nil {
		cache.policies = map[string]cachedLocalPolicy{}
	}
	cache.policies[fmt.Sprintf("%d/%s", projectID, p.DN)] = cachedLocalPolicy{p, time.Now()}
}
func (e *Engine) localPolicy(projectID int64, host string) (domain.PasswordPolicy, bool) {
	cache := e.localPolicyCache
	if cache == nil {
		return domain.PasswordPolicy{}, false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	key := fmt.Sprintf("%d/%s", projectID, host)
	p, ok := cache.policies[key]
	if !ok || time.Since(p.at) > 15*time.Minute {
		delete(cache.policies, key)
		return domain.PasswordPolicy{}, false
	}
	return p.policy, true
}

// SprayLocalCredentials never falls back to a domain identity. Missing/ambiguous
// machine identity and unknown/DC machine roles are skipped before login.
func (e *Engine) SprayLocalCredentials(ctx context.Context, p domain.Project, targets []domain.Service, creds []domain.Credential, o LocalSprayOptions) (*SprayResult, error) {
	return e.sprayLocalCredentials(ctx, p, targets, creds, o, func(ctx context.Context, t domain.Service, timeout time.Duration) (discovery.SMBIdentity, error) {
		return e.discoverLocalMachine(ctx, p.ID, t, timeout)
	}, tryLogin)
}

func (e *Engine) discoverLocalMachine(ctx context.Context, projectID int64, t domain.Service, timeout time.Duration) (discovery.SMBIdentity, error) {
	id, err := discoverLocalTarget(ctx, t, timeout, e.config.LibraryDir)
	if err != nil && ctx.Err() == nil && strings.HasPrefix(err.Error(), "роль машины не прочитана") {
		if _, ok := e.localPolicy(projectID, t.Host); ok {
			role := 1
			id.MachineRole = &role
			id.RoleSource = "recent WinRM local SAM policy"
			return id, nil
		}
	}
	return id, err
}

func localCredential(cred domain.Credential, id discovery.SMBIdentity) (domain.Credential, error) {
	if id.MachineRole == nil || *id.MachineRole < 0 || *id.MachineRole >= 4 || id.ComputerName == "" {
		return cred, fmt.Errorf("DC или неизвестная локальная область: попытка не отправлена")
	}
	if strings.ContainsAny(id.ComputerName, "/\\@.: \t\r\n") || len(id.ComputerName) > 15 {
		return cred, fmt.Errorf("некорректное NetBIOS-имя")
	}
	if strings.ContainsAny(cred.Username, "/\\@\x00\r\n") || strings.TrimSpace(cred.Username) == "" {
		return cred, fmt.Errorf("локальное имя должно быть задано без домена")
	}
	if cred.Type != "password" && cred.Type != "ntlm-hash" {
		return cred, fmt.Errorf("локальный SMB: требуется пароль или NTLM-хеш")
	}
	if cred.Domain != "" && cred.Domain != "." && !strings.EqualFold(cred.Domain, id.ComputerName) {
		return cred, fmt.Errorf("доменная учётка запрещена в локальном режиме")
	}
	cred.Domain = id.ComputerName
	return cred, nil
}

func discoverLocalTarget(ctx context.Context, target domain.Service, timeout time.Duration, library string) (discovery.SMBIdentity, error) {
	id, e := discovery.ProbeSMBIdentity(ctx, target.Host, target.Port, timeout)
	if e != nil {
		return id, e
	}
	// If LDAP is reachable, fail closed on an unreadable role; DCs have no local SAM.
	c, e := ldap.DialURL("ldap://"+net.JoinHostPort(target.Host, "389"), ldap.DialWithDialer(&net.Dialer{Timeout: min(timeout, 2*time.Second)}))
	if e == nil {
		defer c.Close()
		c.SetTimeout(min(timeout, 2*time.Second))
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		root, e := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 2, false, "(objectClass=*)", []string{"supportedCapabilities"}, nil))
		if e != nil {
			return id, fmt.Errorf("роль LDAP-сервера неизвестна: %w", e)
		}
		for _, entry := range root.Entries {
			for _, v := range entry.GetAttributeValues("supportedCapabilities") {
				if v == "1.2.840.113556.1.4.800" {
					return id, fmt.Errorf("контроллер AD исключён из локального перебора")
				}
			}
		}
	}
	role, roleErr := js.ReadMachineRole(ctx, target.Host, target.Port, min(timeout, 3*time.Second))
	if roleErr == nil {
		id.MachineRole = &role
		id.RoleSource = "DSROLE"
	} else if library != "" {
		runner := nse.New(library, nse.Config{Timeout: 2 * time.Second, ScriptTimeout: 5 * time.Second, RPS: 2, SelectedServicesOnly: true, Args: map[string]string{"smbnoguest": "true"}})
		results, _, err := runner.Run(ctx, filepath.Join(library, "nmap/scripts/smb-os-discovery.nse"), nse.HostInfo{IP: target.Host}, []nse.PortInfo{{Number: target.Port, Protocol: "tcp", State: "open", Service: "microsoft-ds"}})
		if err == nil {
			for _, result := range results {
				for _, line := range strings.Split(result.Output, "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "OS: Windows ") && !strings.Contains(line, "Server") {
						for _, version := range []string{"XP", "Vista", "7", "8", "10", "11"} {
							prefix := "OS: Windows " + version
							if strings.HasPrefix(line, prefix+" ") || strings.HasPrefix(line, prefix+".") {
								member := 1
								id.MachineRole = &member
								id.RoleSource = "SMB OS: Windows client edition"
							}
						}
					}
				}
			}
		}
	}
	if id.MachineRole == nil {
		return id, fmt.Errorf("роль машины не прочитана: %v; локальные попытки не отправлены", roleErr)
	}
	return id, ctx.Err()
}

func localAttemptKey(host, user string) string {
	return "local:" + strings.ToLower(host) + "|" + strings.ToLower(user)
}

func (e *Engine) sprayLocalCredentials(ctx context.Context, p domain.Project, targets []domain.Service, creds []domain.Credential, o LocalSprayOptions,
	discover func(context.Context, domain.Service, time.Duration) (discovery.SMBIdentity, error), login func(context.Context, string, time.Duration, string, int, domain.Credential) (bool, error)) (*SprayResult, error) {
	if !p.AllowCredentialAttack {
		return nil, fmt.Errorf("credential attacks are disabled for this project")
	}
	timeout := time.Duration(e.config.TimeoutSeconds) * time.Second
	maxAttempts := p.LockoutMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = domain.DefaultLockoutMaxAttempts
	}
	window := time.Duration(p.LockoutWindowMinutes) * time.Minute
	if window <= 0 {
		window = time.Duration(domain.DefaultLockoutWindowMinutes) * time.Minute
	}
	delay := max(o.Delay, time.Second/time.Duration(max(1, e.config.RPS)))
	type prepared struct {
		identity discovery.SMBIdentity
		err      error
	}
	identities := map[string]prepared{}
	stopped := map[string]bool{}
	var out SprayResult
	last := time.Time{}
	for _, cred := range creds {
		for _, target := range targets {
			if e := ctx.Err(); e != nil {
				return &out, e
			}
			a := domain.AuthAttempt{Target: target.Host, Port: target.Port, Protocol: "smb", Username: cred.Username, Domain: cred.Domain, Local: true}
			skip := func(reason string) { a.Skipped = true; a.Error = reason; out.Attempts = append(out.Attempts, a) }
			if target.Protocol != "smb" && target.Name != "microsoft-ds" {
				skip("локальный режим поддерживает SMB; другой протокол не используется")
				continue
			}
			addr := net.JoinHostPort(target.Host, fmt.Sprint(target.Port))
			id, seen := identities[addr]
			if !seen {
				identity, e := discover(ctx, target, timeout)
				id = prepared{identity, e}
				identities[addr] = id
			}
			if id.err != nil {
				skip(id.err.Error())
				continue
			}
			local, err := localCredential(cred, id.identity)
			if err != nil {
				skip(err.Error())
				continue
			}
			a.Domain = local.Domain
			key := localAttemptKey(target.Host, local.Username)
			if stopped[key] {
				skip("проверки этой локальной учётки завершены")
				continue
			}
			limit, lookback := maxAttempts, window
			policy, knownPolicy := o.Policies[target.Host]
			if !knownPolicy {
				policy, knownPolicy = e.localPolicy(p.ID, target.Host)
			}
			if knownPolicy && policy.Source == "local" && policy.DN == target.Host {
				if policy.LockoutThreshold != nil && *policy.LockoutThreshold > 0 {
					limit = min(limit, int(*policy.LockoutThreshold-1))
				}
				if policy.ObservationWindowSeconds != nil {
					lookback = max(lookback, time.Duration(min(*policy.ObservationWindowSeconds, int64(86400*365)))*time.Second)
				}
			}
			failures, err := e.store.RecentFailureCount(ctx, p.ID, key, time.Now().Add(-lookback))
			if err != nil {
				return &out, err
			}
			if failures >= limit {
				skip("лимит неудач локальной учётки достигнут")
				continue
			}
			if wait := delay - time.Since(last); wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return &out, ctx.Err()
				case <-timer.C:
				}
			}
			last = time.Now()
			a.Success, err = login(ctx, "smb", timeout, target.Host, target.Port, local)
			if err != nil {
				a.Error = err.Error()
			}
			out.Attempts = append(out.Attempts, a)
			recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			recordErr := e.store.RecordAttempt(recordCtx, p.ID, addr, key, "smb-local", a.Success)
			cancel()
			if recordErr != nil {
				return &out, recordErr
			}
			if a.Success || strings.Contains(strings.ToUpper(a.Error), "LOCKED") || strings.Contains(strings.ToUpper(a.Error), "0XC0000234") {
				stopped[key] = true
			}
		}
	}
	return &out, nil
}
