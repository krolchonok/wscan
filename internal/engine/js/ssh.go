package js

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dop251/goja"
	// zgrab2's SSH client, not golang.org/x/crypto/ssh: this is what real
	// nuclei's SSHClient is actually backed by (pkg/js/libs/ssh/ssh.go), and
	// it tolerates server auth-negotiation quirks x/crypto/ssh does not —
	// e.g. a Win32-OpenSSH server offering keyboard-interactive and then
	// replying with a bare USERAUTH_FAILURE made x/crypto/ssh panic with
	// "unexpected message type 51 (expected 60)" instead of just reporting a
	// clean auth failure, on every single credential attempt.
	ssh "github.com/zmap/zgrab2/lib/ssh"
)

// sshModule exposes SSHClient as a goja constructor — see smbModule's doc
// comment for why a plain FunctionCall-shaped factory isn't enough.
func sshModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	obj := vm.NewObject()
	ctor := func(call goja.ConstructorCall) *goja.Object {
		return vm.ToValue(&SSHClient{ctx: ctx, timeout: timeout}).(*goja.Object)
	}
	_ = obj.Set("SSHClient", ctor)
	return obj
}

// SSHClient mirrors nuclei/ssh.SSHClient.
type SSHClient struct {
	ctx        context.Context
	timeout    time.Duration
	connection *ssh.Client
}

// HandshakeInfo is returned by ConnectSSHInfoMode (nuclei/zgrab shape, subset).
type HandshakeInfo struct {
	Banner    string       `json:"Banner"`
	UserAuth  []string     `json:"UserAuth"`
	ServerID  *SSHServerID `json:"ServerID"`
	ServerKex *SSHKexInfo  `json:"ServerKex,omitempty"`
}

type SSHServerID struct {
	Raw             string `json:"Raw"`
	ProtoVersion    string `json:"ProtoVersion"`
	SoftwareVersion string `json:"SoftwareVersion"`
	Comment         string `json:"Comment"`
}

// SSHKexInfo mirrors the exported fields of zgrab2/lib/ssh's own (unexported)
// kexInitMsg — field names, not json tags, since CVE-2023-48795.yaml
// (Terrapin attack) reads them straight off the JS object:
// response.ServerKex.CiphersClientServer, .CiphersServerClient,
// .MACsClientServer, .MACsServerClient, .KexAlgos.
type SSHKexInfo struct {
	KexAlgos            []string `json:"KexAlgos"`
	CiphersClientServer []string `json:"CiphersClientServer"`
	CiphersServerClient []string `json:"CiphersServerClient"`
	MACsClientServer    []string `json:"MACsClientServer"`
	MACsServerClient    []string `json:"MACsServerClient"`
}

// NewSSHClient constructs an SSHClient for direct use outside the goja
// runtime — the credential-spray engine (internal/engine) calls Connect
// straight off this, with no JS VM involved at all.
func NewSSHClient(ctx context.Context, timeout time.Duration) *SSHClient {
	return &SSHClient{ctx: ctx, timeout: timeout}
}

func (c *SSHClient) SetTimeout(sec int) {
	if sec > 0 {
		c.timeout = time.Duration(sec) * time.Second
	}
}

func (c *SSHClient) Connect(host string, port int, username, password string) (bool, error) {
	client, err := c.dial(host, port, username, []ssh.AuthMethod{
		ssh.Password(password),
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = password
			}
			return answers, nil
		}),
	})
	if err != nil {
		return false, err
	}
	c.connection = client
	return true, nil
}

// ConnectPassword sends only password authentication. Dictionary attempts must
// not retry the same secret with keyboard-interactive on the same connection.
func (c *SSHClient) ConnectPassword(host string, port int, username, password string) (bool, error) {
	client, err := c.dial(host, port, username, []ssh.AuthMethod{ssh.Password(password)})
	if err != nil {
		return false, err
	}
	c.connection = client
	return true, nil
}

func (c *SSHClient) ConnectWithKey(host string, port int, username, key string) (bool, error) {
	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		return false, err
	}
	client, err := c.dial(host, port, username, []ssh.AuthMethod{ssh.PublicKeys(signer)})
	if err != nil {
		return false, err
	}
	c.connection = client
	return true, nil
}

func (c *SSHClient) ConnectSSHInfoMode(host string, port int) (*HandshakeInfo, error) {
	if cache, ok := c.ctx.Value(sshInfoCacheKey{}).(*sshInfoCache); ok {
		return cache.get(c.ctx, joinAddr(host, port), func() (*HandshakeInfo, error) { return c.collectSSHInfo(host, port) })
	}
	return c.collectSSHInfo(host, port)
}

func (c *SSHClient) collectSSHInfo(host string, port int) (*HandshakeInfo, error) {
	info := &HandshakeInfo{}
	connLog := &ssh.HandshakeLog{}
	cfg := &ssh.ClientConfig{
		User:             "probe",
		DontAuthenticate: true,
		CollectUserAuth:  true,
		HostKeyCallback:  ssh.InsecureIgnoreHostKey(),
		Timeout:          c.timeout,
		BannerCallback: func(banner string) error {
			info.Banner = strings.TrimSpace(banner)
			return nil
		},
	}
	cfg.ConnLog = connLog
	addr := joinAddr(host, port)
	d := net.Dialer{Timeout: c.timeout}
	raw, err := d.DialContext(c.ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	stop := context.AfterFunc(c.ctx, func() { _ = raw.Close() })
	defer stop()
	_ = raw.SetDeadline(sshDeadline(c.ctx, c.timeout))

	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		return nil, err
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()
	info.UserAuth = append([]string{}, connLog.UserAuth...)
	if id := connLog.ServerID; id != nil {
		info.ServerID = &SSHServerID{Raw: id.Raw, ProtoVersion: id.ProtoVersion, SoftwareVersion: id.SoftwareVersion, Comment: id.Comment}
	}
	info.ServerKex = sshKexInfoFromLog(connLog)
	return info, nil
}

// sshKexInfoFromLog copies the fields CVE-2023-48795.yaml needs out of
// zgrab2's own ConnLog.ServerKex — set as a side effect of the handshake
// itself (handshake.go's kexInitMsg exchange), regardless of whether
// authentication that follows it succeeds or fails, so it's always populated
// by the time NewClientConn returns either way above.
func sshKexInfoFromLog(connLog *ssh.HandshakeLog) *SSHKexInfo {
	if connLog == nil || connLog.ServerKex == nil {
		return nil
	}
	k := connLog.ServerKex
	return &SSHKexInfo{
		KexAlgos:            k.KexAlgos,
		CiphersClientServer: k.CiphersClientServer,
		CiphersServerClient: k.CiphersServerClient,
		MACsClientServer:    k.MACsClientServer,
		MACsServerClient:    k.MACsServerClient,
	}
}

func (c *SSHClient) Run(cmd string) (string, error) {
	if c.connection == nil {
		return "", fmt.Errorf("no connection")
	}
	session, err := c.connection.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	out, err := session.CombinedOutput(cmd)
	return string(out), err
}

func (c *SSHClient) Close() (bool, error) {
	if c.connection == nil {
		return true, nil
	}
	err := c.connection.Close()
	c.connection = nil
	return err == nil, err
}

func (c *SSHClient) dial(host string, port int, user string, auth []ssh.AuthMethod) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         c.timeout,
	}
	addr := joinAddr(host, port)
	d := net.Dialer{Timeout: c.timeout}
	raw, err := d.DialContext(c.ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(c.ctx, func() { _ = raw.Close() })
	defer stop()
	_ = raw.SetDeadline(sshDeadline(c.ctx, c.timeout))
	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return ssh.NewClient(conn, chans, reqs), nil
}

func sshDeadline(ctx context.Context, timeout time.Duration) time.Time {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return deadline
}

func parseSSHAuthMethods(errMsg string) []string {
	// Example: "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain"
	lower := strings.ToLower(errMsg)
	var out []string
	for _, m := range []string{"password", "publickey", "keyboard-interactive", "gssapi-with-mic"} {
		if strings.Contains(lower, m) {
			out = append(out, m)
		}
	}
	return out
}
