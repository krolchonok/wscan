package js

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/go-ldap/ldap/v3"
)

// ldapModule exposes LDAPClient as a goja constructor matching real nuclei's
// pkg/js/libs/ldap shape exactly (`new ldap.Client(ldapUrl, realm, cfg?)`,
// `new ldap.Config()`) — upstream nuclei-templates/javascript/*/ldap/*.yaml
// call these names directly. Unlike nuclei's own version, this dials with a
// plain context-aware net.Dialer instead of its fastdialer/host-allow-policy
// machinery, the same simplification every other native client in this
// package already makes (ssh.go, smb.go, ...).
func ldapModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	obj := vm.NewObject()
	clientCtor := func(call goja.ConstructorCall) *goja.Object {
		rawURL, _ := call.Argument(0).Export().(string)
		realm, _ := call.Argument(1).Export().(string)
		if rawURL == "" {
			panic(vm.ToValue("ldap url cannot be empty"))
		}
		if realm == "" {
			panic(vm.ToValue("realm cannot be empty"))
		}
		var cfg LDAPConfig
		if len(call.Arguments) > 2 {
			if c, ok := call.Argument(2).Export().(*LDAPConfig); ok && c != nil {
				cfg = *c
			}
		}
		clientTimeout := timeout
		if cfg.Timeout > 0 {
			clientTimeout = time.Duration(cfg.Timeout) * time.Second
		}
		c, err := dialLDAPURL(ctx, clientTimeout, rawURL, cfg)
		if err != nil {
			panic(vm.ToValue(fmt.Sprintf("failed to connect to ldap server: %s", err)))
		}
		c.Realm = realm
		c.BaseDN = baseDNFromRealm(realm)
		return vm.ToValue(c).(*goja.Object)
	}
	_ = obj.Set("Client", clientCtor)

	cfgCtor := func(call goja.ConstructorCall) *goja.Object {
		return vm.ToValue(&LDAPConfig{}).(*goja.Object)
	}
	_ = obj.Set("Config", cfgCtor)

	_ = obj.Set("DecodeSID", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(DecodeSID(call.Argument(0).String()))
	})
	_ = obj.Set("DecodeADTimestamp", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(DecodeADTimestamp(call.Argument(0).String()))
	})
	_ = obj.Set("DecodeZuluTimestamp", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(DecodeZuluTimestamp(call.Argument(0).String()))
	})
	_ = obj.Set("JoinFilters", func(call goja.FunctionCall) goja.Value {
		filters := make([]string, len(call.Arguments))
		for i, a := range call.Arguments {
			filters[i] = a.String()
		}
		return vm.ToValue(JoinFilters(filters...))
	})
	_ = obj.Set("NegativeFilter", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(NegativeFilter(call.Argument(0).String()))
	})
	for name, value := range ldapFilterConstants {
		_ = obj.Set(name, value)
	}
	_ = obj.Set("ScopeBaseObject", ldap.ScopeBaseObject)
	_ = obj.Set("ScopeSingleLevel", ldap.ScopeSingleLevel)
	_ = obj.Set("ScopeWholeSubtree", ldap.ScopeWholeSubtree)
	_ = obj.Set("NeverDerefAliases", ldap.NeverDerefAliases)
	return obj
}

// LDAPClient mirrors nuclei/ldap.Client field-for-field (json tags matter:
// goja's TagFieldNameMapper hides any untagged field from JS entirely — see
// SSHKexInfo's history in ssh.go for why every field here is tagged).
type LDAPClient struct {
	Host   string `json:"Host"`
	Port   int    `json:"Port"`
	Realm  string `json:"Realm"`
	BaseDN string `json:"BaseDN"`

	conn    *ldap.Conn
	timeout time.Duration
}

// LDAPConfig mirrors nuclei/ldap.Config — constructed via `new ldap.Config()`
// and then mutated field-by-field from JS before being passed as the third
// argument to `new ldap.Client(...)`, so every field needs a json tag for
// the same reason as LDAPClient's.
type LDAPConfig struct {
	Timeout    int    `json:"Timeout"`
	ServerName string `json:"ServerName"`
	Upgrade    bool   `json:"Upgrade"`
}

func baseDNFromRealm(realm string) string {
	return "dc=" + strings.Join(strings.Split(realm, "."), ",dc=")
}

// dialLDAPURL parses an ldap://, ldaps:// URL (defaulting to ldap:// when no
// scheme is given — nuclei-templates/javascript ldap calls sometimes pass a
// bare host) and returns a connected, bound-ready *LDAPClient.
func dialLDAPURL(ctx context.Context, timeout time.Duration, rawURL string, cfg LDAPConfig) (*LDAPClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		u = &url.URL{Scheme: "ldap", Host: rawURL}
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "ldap"
	}
	host := u.Hostname()
	if host == "" {
		host = u.Host
	}
	port := u.Port()

	switch scheme {
	case "ldap", "ldaps":
	default:
		return nil, fmt.Errorf("unsupported ldap url schema %q", scheme)
	}
	return dialLDAPHostPort(ctx, timeout, scheme, host, port, cfg)
}

// dialLDAPHostPort is dialLDAPURL's host/port-already-split counterpart —
// what NewLDAPClient (the credential-spray engine's entry point, no URL
// parsing involved) calls directly.
func dialLDAPHostPort(ctx context.Context, timeout time.Duration, scheme, host, port string, cfg LDAPConfig) (*LDAPClient, error) {
	serverName := host
	if cfg.ServerName != "" {
		serverName = cfg.ServerName
	}
	d := net.Dialer{Timeout: timeout}

	var conn *ldap.Conn
	var portNum int
	switch scheme {
	case "ldaps":
		if port == "" {
			port = ldap.DefaultLdapsPort
		}
		tlsConn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(host, port), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, ServerName: serverName})
		if err != nil {
			return nil, err
		}
		conn = ldap.NewConn(tlsConn, true)
		conn.Start()
	default: // "ldap"
		if port == "" {
			port = ldap.DefaultLdapPort
		}
		netConn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return nil, err
		}
		conn = ldap.NewConn(netConn, false)
		if cfg.Upgrade {
			if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: true, ServerName: serverName}); err != nil {
				_ = conn.Close()
				return nil, err
			}
		} else {
			conn.Start()
		}
	}
	portNum, _ = strconv.Atoi(port)
	return &LDAPClient{Host: host, Port: portNum, conn: conn, timeout: timeout}, nil
}

// NewLDAPClient dials host:port directly (plain ldap://, or ldaps:// when
// useTLS is true) for direct use outside the goja runtime — the
// credential-spray engine (internal/engine) calls Authenticate /
// AuthenticateWithNTLMHash straight off this, no JS VM involved.
func NewLDAPClient(ctx context.Context, timeout time.Duration, useTLS bool, host string, port int, realm string) (*LDAPClient, error) {
	scheme := "ldap"
	if useTLS {
		scheme = "ldaps"
	}
	c, err := dialLDAPHostPort(ctx, timeout, scheme, host, strconv.Itoa(port), LDAPConfig{})
	if err != nil {
		return nil, err
	}
	c.Realm = realm
	c.BaseDN = baseDNFromRealm(realm)
	return c, nil
}

// Authenticate tries NTLMBind first (the realm as NTLM domain), then falls
// back to a plain simple bind (or an unauthenticated bind for an empty
// password) — same fallback order as nuclei's own Client.Authenticate.
func (c *LDAPClient) Authenticate(username, password string) (bool, error) {
	if c.conn == nil {
		return false, fmt.Errorf("no existing connection")
	}
	if err := c.conn.NTLMBind(c.Realm, username, password); err == nil {
		return true, nil
	}
	var err error
	if password == "" {
		err = c.conn.UnauthenticatedBind(username)
	} else {
		err = c.conn.Bind(username, password)
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// AuthenticateWithNTLMHash authenticates via pass-the-hash (NTLM hash
// instead of a plaintext password) — backs domain.Credential{Type:
// "ntlm-hash"} in the credential-spray engine.
func (c *LDAPClient) AuthenticateWithNTLMHash(username, hash string) (bool, error) {
	if c.conn == nil {
		return false, fmt.Errorf("no existing connection")
	}
	if err := c.conn.NTLMBindWithHash(c.Realm, username, hash); err != nil {
		return false, err
	}
	return true, nil
}

// Search runs a whole-subtree search under BaseDN — matches nuclei's
// Client.Search(filter, ...attributes).
func (c *LDAPClient) Search(filter string, attributes ...string) (*SearchResult, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("no existing connection")
	}
	if c.BaseDN == "" {
		c.BaseDN = baseDNFromRealm(c.Realm)
	}
	if len(attributes) == 0 {
		return nil, fmt.Errorf("attributes cannot be empty")
	}
	res, err := c.conn.Search(ldap.NewSearchRequest(
		c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attributes, nil,
	))
	if err != nil {
		return nil, err
	}
	return getSearchResult(res), nil
}

// CollectMetadata reads the server's Root DSE — a low-cost, unauthenticated
// or anonymous-bind-friendly probe for domain/forest functionality level and
// DC hostname, matching nuclei's Client.CollectMetadata.
func (c *LDAPClient) CollectMetadata() (*LDAPMetadata, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("no existing connection")
	}
	metadata := &LDAPMetadata{Domain: c.Realm, BaseDN: c.BaseDN}
	if metadata.BaseDN == "" {
		metadata.BaseDN = baseDNFromRealm(c.Realm)
	}
	res, err := c.conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "domainFunctionality", "forestFunctionality", "domainControllerFunctionality", "dnsHostName"},
		nil,
	))
	if err != nil {
		return nil, err
	}
	for _, entry := range res.Entries {
		for _, attr := range entry.Attributes {
			value := entry.GetAttributeValue(attr.Name)
			switch attr.Name {
			case "defaultNamingContext":
				metadata.DefaultNamingContext = value
			case "domainFunctionality":
				metadata.DomainFunctionality = value
			case "forestFunctionality":
				metadata.ForestFunctionality = value
			case "domainControllerFunctionality":
				metadata.DomainControllerFunctionality = value
			case "dnsHostName":
				metadata.DnsHostName = value
			}
		}
	}
	return metadata, nil
}

// GetVersion returns the Root DSE's supportedLDAPVersion values.
func (c *LDAPClient) GetVersion() ([]string, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("no existing connection")
	}
	res, err := c.conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"supportedLDAPVersion"}, nil,
	))
	if err != nil {
		return nil, err
	}
	if len(res.Entries) > 0 {
		return res.Entries[0].GetAttributeValues("supportedLDAPVersion"), nil
	}
	return []string{"unknown"}, nil
}

func (c *LDAPClient) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// LDAPMetadata mirrors nuclei/ldap.Metadata.
type LDAPMetadata struct {
	BaseDN                        string `json:"BaseDN"`
	Domain                        string `json:"Domain"`
	DefaultNamingContext          string `json:"DefaultNamingContext"`
	DomainFunctionality           string `json:"DomainFunctionality"`
	ForestFunctionality           string `json:"ForestFunctionality"`
	DomainControllerFunctionality string `json:"DomainControllerFunctionality"`
	DnsHostName                   string `json:"DnsHostName"`
}
