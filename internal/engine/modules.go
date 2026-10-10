package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"wscan/internal/domain"
	"wscan/internal/engine/js"
)

// ModuleFunc runs one post-auth enumeration module against a target with an
// already-known-working (or assumed-working — it authenticates itself)
// credential. args carries module-specific parameters (e.g. "command" for
// winrm-exec); most modules ignore it.
type ModuleFunc func(ctx context.Context, timeout time.Duration, host string, port int, cred domain.Credential, args map[string]string) (any, error)

// ModuleInfo describes one registered module for discovery (the TUI module
// picker lists these, grouped by Protocol).
type ModuleInfo struct {
	Name        string
	Protocol    string
	Description string
}

// moduleCatalog is deliberately read-only enumeration for every module
// except winrm-exec: the project plan's Phase 4 scope explicitly excludes
// secret-dumping/destructive modules (SAM/LSA dump, file write, process
// injection, ...) from this first pass — those would need the same
// explicit-opt-in weight as AllowExploit, not bundled in here by default.
// winrm-exec is the one deliberate exception: arbitrary command execution is
// the actual point of validating a WinRM credential (nxc's core use case),
// so excluding it would make AllowCredentialAttack+WinRM pointless — it is
// still gated behind AllowCredentialAttack like every other module here.
var moduleCatalog = []ModuleInfo{
	{"smb-configs", "smb", "Ограниченный поиск конфигураций в выбранной шаре; секреты скрыты"},
	{"ldap-users", "ldap", "All AD user objects (FilterIsPerson)"},
	{"ldap-active-users", "ldap", "AD users that are not disabled"},
	{"ldap-admins", "ldap", "Enabled AD users with adminCount=1"},
	{"ldap-groups", "ldap", "All AD group objects"},
	{"ldap-dc-list", "ldap", "Enabled domain controller computer objects"},
	{"ldap-kerberoastable", "ldap", "Enabled users with a servicePrincipalName (kerberoastable)"},
	{"ldap-asrep-roastable", "ldap", "Users with Kerberos pre-auth disabled (AS-REP roastable)"},
	{"ldap-never-expiring-passwords", "ldap", "Users whose password never expires"},
	{"ldap-password-not-required", "ldap", "Users with PASSWD_NOTREQD set"},
	{"ldap-trusted-for-delegation", "ldap", "Users trusted for unconstrained Kerberos delegation"},
	{"ldap-domain-sid", "ldap", "The domain's SID"},
	{"ldap-metadata", "ldap", "Root DSE metadata (domain/forest functionality, DC hostname)"},
	{"smb-shares", "smb", "Шары и доступ на чтение; запись не проверяется"},
	{"winrm-whoami", "winrm", "Run \"whoami\" over an authenticated WinRM session"},
	{"winrm-exec", "winrm", "Run an operator-supplied command over WinRM (requires args[\"command\"])"},
}

var moduleCatalogIndex = func() map[string]ModuleFunc {
	index := map[string]ModuleFunc{
		"ldap-users":                    ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADUsers() }),
		"ldap-active-users":             ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADActiveUsers() }),
		"ldap-admins":                   ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADAdmins() }),
		"ldap-groups":                   ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADGroups() }),
		"ldap-dc-list":                  ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADDCList() }),
		"ldap-kerberoastable":           ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADUserKerberoastable() }),
		"ldap-asrep-roastable":          ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADUserAsRepRoastable() }),
		"ldap-never-expiring-passwords": ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADUserWithNeverExpiringPasswords() }),
		"ldap-password-not-required":    ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADUserWithPasswordNotRequired() }),
		"ldap-trusted-for-delegation":   ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADUserTrustedForDelegation() }),
		"ldap-domain-sid":               ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.GetADDomainSID() }),
		"ldap-metadata":                 ldapModuleFunc(func(c *js.LDAPClient) (any, error) { return c.CollectMetadata() }),

		"smb-shares": func(ctx context.Context, timeout time.Duration, host string, port int, cred domain.Credential, _ map[string]string) (any, error) {
			return js.BrowseSMBWithOptions(ctx, js.SMBBrowseOptions{Host: host, Port: port, Mode: "credential", Credential: cred}, "", "")
		},
		"smb-configs": func(ctx context.Context, timeout time.Duration, host string, port int, cred domain.Credential, args map[string]string) (any, error) {
			return js.FindSMBConfigs(ctx, js.SMBBrowseOptions{Host: host, Port: port, Mode: "credential", Credential: cred}, args["share"], args["path"])
		},

		"winrm-whoami": func(ctx context.Context, timeout time.Duration, host string, port int, cred domain.Credential, _ map[string]string) (any, error) {
			return winrmRun(ctx, timeout, host, port, cred, "whoami")
		},
		"winrm-exec": func(ctx context.Context, timeout time.Duration, host string, port int, cred domain.Credential, args map[string]string) (any, error) {
			cmd := args["command"]
			if cmd == "" {
				return nil, fmt.Errorf(`winrm-exec requires args["command"]`)
			}
			return winrmRun(ctx, timeout, host, port, cred, cmd)
		},
	}
	names := []string{}
	for name := range js.MSSQLAuditQueries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, module := range names {
		name := module
		index["mssql-"+name] = func(ctx context.Context, timeout time.Duration, host string, port int, cred domain.Credential, args map[string]string) (any, error) {
			if cred.Type != "password" {
				return nil, fmt.Errorf("MSSQL требует пароль")
			}
			session, err := js.OpenMSSQL(ctx, js.MSSQLOptions{Host: host, Port: port, Username: cred.Username, Password: cred.Secret, Domain: cred.Domain, Database: args["database"], Encrypt: true, TrustServerCertificate: args["trust-certificate"] == "true", Timeout: timeout})
			if err != nil {
				return nil, err
			}
			defer session.Close()
			result, err := session.Audit(ctx, name)
			if err != nil {
				return result, &postAuthError{err}
			}
			return result, nil
		}
		moduleCatalog = append(moduleCatalog, ModuleInfo{"mssql-" + name, "mssql", "MSSQL: " + name + " — чтение метаданных"})
	}
	return index
}()

// AvailableModules returns the module catalog, optionally filtered by
// protocol (e.g. "ldap") — empty protocol returns all.
func AvailableModules(protocol string) []ModuleInfo {
	switch protocol {
	case "ms-sql", "ms-sql-s", "sqlserver":
		protocol = "mssql"
	}
	if protocol == "" {
		return moduleCatalog
	}
	var out []ModuleInfo
	for _, m := range moduleCatalog {
		if m.Protocol == protocol {
			out = append(out, m)
		}
	}
	return out
}

// WinRMOutput is winrm-whoami/winrm-exec's result shape.
type WinRMOutput struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

func winrmRun(ctx context.Context, timeout time.Duration, host string, port int, cred domain.Credential, command string) (*WinRMOutput, error) {
	if cred.Type != "password" {
		return nil, fmt.Errorf("WinRM сейчас поддерживает только учётные данные с паролем")
	}
	stdout, stderr, code, err := js.NewWinRMClient(ctx, timeout).RunCommand(host, port, cred.Domain, cred.Username, cred.Secret, command)
	if err != nil {
		return nil, err
	}
	return &WinRMOutput{Stdout: stdout, Stderr: stderr, ExitCode: code}, nil
}

// ldapModuleFunc wraps an already-authenticated-LDAPClient call into a
// ModuleFunc: dial, authenticate with cred (password or, for
// Credential.Type == "ntlm-hash", pass-the-hash), run call, close.
func ldapModuleFunc(call func(c *js.LDAPClient) (any, error)) ModuleFunc {
	return func(ctx context.Context, timeout time.Duration, host string, port int, cred domain.Credential, _ map[string]string) (any, error) {
		c, err := js.NewLDAPClient(ctx, timeout, false, host, port, cred.Domain)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		var ok bool
		if cred.Type == "ntlm-hash" {
			ok, err = c.AuthenticateWithNTLMHash(cred.Username, cred.Secret)
		} else {
			ok, err = c.Authenticate(cred.Username, cred.Secret)
		}
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("ldap authentication failed")
		}
		return call(c)
	}
}

// RunModule runs one post-auth enumeration module (see moduleCatalog)
// against target with cred. Gated by the same AllowCredentialAttack project
// setting as SprayCredentials — a module call is still "use this credential
// against this target", the same risk category, just after validity is
// already assumed rather than being tested. The attempt is recorded through
// the same RecordAttempt ledger SprayCredentials uses (see
// internal/storage.Store.RecentFailureCount's doc comment) so a credential
// that stops working between validation and later module runs still
// contributes to the project's lockout-safety accounting.
func (e *Engine) RunModule(ctx context.Context, p domain.Project, target domain.Service, cred domain.Credential, moduleName string, args map[string]string) (*domain.ModuleResult, error) {
	if !p.AllowCredentialAttack {
		return nil, fmt.Errorf("credential attacks are disabled for this project (enable AllowCredentialAttack)")
	}
	fn, ok := moduleCatalogIndex[moduleName]
	if !ok {
		return nil, fmt.Errorf("unknown module %q", moduleName)
	}

	timeout := time.Duration(e.config.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	data, runErr := fn(ctx, timeout, target.Host, target.Port, cred, args)
	result := &domain.ModuleResult{
		Target:   target.Host,
		Port:     target.Port,
		Protocol: target.Protocol,
		Module:   moduleName,
		Data:     data,
	}
	if runErr != nil {
		result.Error = runErr.Error()
	}

	addr := target.Host
	if target.Port != 0 {
		addr = fmt.Sprintf("%s:%d", target.Host, target.Port)
	}
	authenticated := runErr == nil
	var queryErr *postAuthError
	if errors.As(runErr, &queryErr) {
		authenticated = true
	}
	if err := e.store.RecordAttempt(ctx, p.ID, addr, cred.Username, target.Protocol, authenticated); err != nil {
		return result, err
	}
	return result, nil
}

// A denied metadata query is not a failed password attempt.
type postAuthError struct{ err error }

func (e *postAuthError) Error() string { return e.err.Error() }
func (e *postAuthError) Unwrap() error { return e.err }
