package js

import (
	"context"
	"time"

	"github.com/masterzen/winrm"
	"wscan/internal/domain"
)

// WinRMClient is a native WinRM client for credential login validation and
// command execution against Windows hosts. Unlike every other client in
// this package, it has no upstream nuclei/pkg/js/libs counterpart to
// port — nuclei itself has no WinRM support — so this is new, not a port,
// and is not wired into the goja module table. It backs credential checks
// and post-auth command modules; the interaction menu uses WinRMOptions.
type WinRMClient struct {
	ctx     context.Context
	timeout time.Duration
}

func NewWinRMClient(ctx context.Context, timeout time.Duration) *WinRMClient {
	return &WinRMClient{ctx: ctx, timeout: timeout}
}

// identity formats a WinRM/NTLM identity as DOMAIN\user when a domain is
// given, matching the convention every Windows NTLM transport expects.
func identity(domainName, username string) string {
	if domainName == "" {
		return username
	}
	return domainName + `\` + username
}

func (c *WinRMClient) client(host string, port int, domainName, username, password string) (*winrm.Client, error) {
	return newInteractionWinRM(c.ctx, WinRMOptions{Host: host, Port: port, HTTPS: port == 5986, Timeout: c.timeout, Credential: domain.Credential{Type: "password", Domain: domainName, Username: username, Secret: password}})
}

// Connect validates a credential by running a harmless no-op command over
// WinRM. The protocol is stateless HTTP — there is no separate "authenticate"
// step — so an invalid credential only surfaces as this first request's
// result (typically an HTTP 401 surfaced as an error here).
func (c *WinRMClient) Connect(host string, port int, domainName, username, password string) (bool, error) {
	client, err := c.client(host, port, domainName, username, password)
	if err != nil {
		return false, err
	}
	if _, _, _, err := client.RunWithContextWithString(c.ctx, "exit 0", ""); err != nil {
		return false, err
	}
	return true, nil
}

// RunCommand executes a command over an already-valid credential and returns
// stdout/stderr/exit code — the post-auth primitive later enumeration
// modules (Phase 4) build on.
func (c *WinRMClient) RunCommand(host string, port int, domainName, username, password, command string) (string, string, int, error) {
	client, err := c.client(host, port, domainName, username, password)
	if err != nil {
		return "", "", 0, err
	}
	return client.RunWithContextWithString(c.ctx, command, "")
}
