package engine

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"wscan/internal/domain"
	"wscan/internal/engine/js"
	"wscan/internal/telnet"
)

// SprayResult is the output of SprayCredentials: one AuthAttempt per
// credential x target pair that was either tried or deliberately skipped.
type SprayResult struct {
	Attempts []domain.AuthAttempt
}

// SprayCredentials tries every credential against every target service, in a
// lockout-safe order: the outer loop is credentials, not targets, so a
// password is tried once across many usernames/hosts before moving to the
// next password, rather than exhausting every password against one account
// first — the classic safe password-spray shape. Before every single
// attempt, it checks the project's recorded failure count for that username
// (internal/storage.Store.RecentFailureCount, which is deliberately
// project-wide, not per-host/per-protocol — see its doc comment) and skips
// the attempt outright once the project's lockout threshold is reached. This
// is enforced here unconditionally: there is no way to call this function
// and have it send an attempt past the threshold.
func (e *Engine) SprayCredentials(ctx context.Context, p domain.Project, targets []domain.Service, creds []domain.Credential) (*SprayResult, error) {
	return e.sprayCredentials(ctx, p, targets, creds, false, false)
}

func (e *Engine) sprayCredentials(ctx context.Context, p domain.Project, targets []domain.Service, creds []domain.Credential, sshPasswordOnly, unlimited bool) (*SprayResult, error) {
	if !p.AllowCredentialAttack {
		return nil, fmt.Errorf("credential attacks are disabled for this project (enable AllowCredentialAttack)")
	}

	maxAttempts := p.LockoutMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = domain.DefaultLockoutMaxAttempts
	}
	windowMinutes := p.LockoutWindowMinutes
	if windowMinutes <= 0 {
		windowMinutes = domain.DefaultLockoutWindowMinutes
	}
	window := time.Duration(windowMinutes) * time.Minute

	timeout := time.Duration(e.config.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	var out SprayResult
	for _, cred := range creds {
		for _, target := range targets {
			if (target.Protocol == "tcp" || target.Protocol == "") && strings.EqualFold(target.Name, "telnet") {
				target.Protocol = "telnet"
			}
			if target.Protocol == "telnet" && (target.Port == 992 || target.Tunnel == "ssl" || target.Tunnel == "tls") {
				return &out, fmt.Errorf("Telnet: TLS listener unsupported; plaintext credentials will not be sent")
			}
			if err := ctx.Err(); err != nil {
				return &out, err
			}

			if !unlimited {
				since := time.Now().Add(-window)
				failures, err := e.store.RecentFailureCount(ctx, p.ID, cred.Username, since)
				if err != nil {
					return &out, err
				}
				if failures >= maxAttempts {
					out.Attempts = append(out.Attempts, domain.AuthAttempt{
						Target:   target.Host,
						Port:     target.Port,
						Protocol: target.Protocol,
						Username: cred.Username,
						Domain:   cred.Domain,
						Skipped:  true,
					})
					continue
				}

			}

			var ok bool
			var loginErr error
			if sshPasswordOnly && strings.EqualFold(target.Protocol, "ssh") {
				client := js.NewSSHClient(ctx, timeout)
				ok, loginErr = client.ConnectPassword(target.Host, target.Port, cred.Username, cred.Secret)
				client.Close()
			} else {
				ok, loginErr = tryLogin(ctx, target.Protocol, timeout, target.Host, target.Port, cred)
			}
			attempt := domain.AuthAttempt{
				Target:   target.Host,
				Port:     target.Port,
				Protocol: target.Protocol,
				Username: cred.Username,
				Domain:   cred.Domain,
				Success:  ok,
			}
			if loginErr != nil {
				attempt.Error = loginErr.Error()
			}
			out.Attempts = append(out.Attempts, attempt)

			addr := target.Host
			if target.Port != 0 {
				addr = fmt.Sprintf("%s:%d", target.Host, target.Port)
			}
			recordCtx := ctx
			stopRecord := func() {}
			if ctx.Err() != nil {
				recordCtx, stopRecord = context.WithTimeout(context.Background(), 3*time.Second)
			}
			recordErr := e.store.RecordAttempt(recordCtx, p.ID, addr, cred.Username, target.Protocol, ok)
			stopRecord()
			if recordErr != nil {
				return &out, recordErr
			}
		}
	}
	return &out, nil
}

// tryLogin dispatches one login attempt to the matching native protocol
// client (internal/engine/js) — the same clients javascript: blocks use,
// called directly with no goja VM involved. It takes the full credential
// (not just username/password) because some protocols need Domain (LDAP's
// NTLM realm, WinRM's DOMAIN\user) or branch on Type (SMB/LDAP pass-the-hash
// when Type is "ntlm-hash").
func tryLogin(ctx context.Context, protocol string, timeout time.Duration, host string, port int, cred domain.Credential) (bool, error) {
	isHash := cred.Type == "ntlm-hash"
	switch strings.ToLower(protocol) {
	case "telnet":
		if cred.Type != "" && cred.Type != "password" {
			return false, fmt.Errorf("Telnet: требуется пароль")
		}
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return false, err
		}
		return telnet.Login(ctx, conn, timeout, cred.Username, cred.Secret)
	case "ssh":
		client := js.NewSSHClient(ctx, timeout)
		defer client.Close()
		return client.Connect(host, port, cred.Username, cred.Secret)
	case "smb":
		return js.NewSMBClient(ctx, timeout).LoginUsingCredential(host, port, cred)
	case "mysql":
		return js.NewMySQLClient(ctx, timeout).Connect(host, port, cred.Username, cred.Secret)
	case "mssql", "ms-sql", "ms-sql-s":
		if cred.Type != "password" {
			return false, fmt.Errorf("MSSQL: требуется пароль")
		}
		return js.NewMSSQLClient(ctx, timeout).ConnectWithDomain(host, port, cred.Domain, cred.Username, cred.Secret)
	case "postgres", "postgresql":
		return js.NewPGClient(ctx, timeout).Connect(host, port, cred.Username, cred.Secret)
	case "vnc":
		return js.NewVNCClient(ctx, timeout).Connect(host, port, cred.Secret)
	case "ldap", "ldaps":
		c, err := js.NewLDAPClient(ctx, timeout, strings.ToLower(protocol) == "ldaps", host, port, cred.Domain)
		if err != nil {
			return false, err
		}
		defer c.Close()
		if isHash {
			return c.AuthenticateWithNTLMHash(cred.Username, cred.Secret)
		}
		return c.Authenticate(cred.Username, cred.Secret)
	case "winrm":
		return js.NewWinRMClient(ctx, timeout).Connect(host, port, cred.Domain, cred.Username, cred.Secret)
	default:
		return false, fmt.Errorf("credential spray: unsupported protocol %q", protocol)
	}
}
