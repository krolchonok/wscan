package js

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// AD userAccountControl bitmask filters — matches nuclei/ldap.Filter*
// exactly (http://oid-info.com/get/1.2.840.113556.1.4.803, the
// LDAP_MATCHING_RULE_BIT_AND OID Active Directory uses for these queries).
const (
	FilterIsPerson                   = "(objectCategory=person)"
	FilterIsGroup                    = "(objectCategory=group)"
	FilterIsComputer                 = "(objectCategory=computer)"
	FilterIsAdmin                    = "(adminCount=1)"
	FilterHasServicePrincipalName    = "(servicePrincipalName=*)"
	FilterLogonScript                = "(userAccountControl:1.2.840.113556.1.4.803:=1)"
	FilterAccountDisabled            = "(userAccountControl:1.2.840.113556.1.4.803:=2)"
	FilterAccountEnabled             = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
	FilterHomedirRequired            = "(userAccountControl:1.2.840.113556.1.4.803:=8)"
	FilterLockout                    = "(userAccountControl:1.2.840.113556.1.4.803:=16)"
	FilterPasswordNotRequired        = "(userAccountControl:1.2.840.113556.1.4.803:=32)"
	FilterPasswordCantChange         = "(userAccountControl:1.2.840.113556.1.4.803:=64)"
	FilterCanSendEncryptedPassword   = "(userAccountControl:1.2.840.113556.1.4.803:=128)"
	FilterIsDuplicateAccount         = "(userAccountControl:1.2.840.113556.1.4.803:=256)"
	FilterIsNormalAccount            = "(userAccountControl:1.2.840.113556.1.4.803:=512)"
	FilterInterdomainTrustAccount    = "(userAccountControl:1.2.840.113556.1.4.803:=2048)"
	FilterWorkstationTrustAccount    = "(userAccountControl:1.2.840.113556.1.4.803:=4096)"
	FilterServerTrustAccount         = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
	FilterDontExpirePassword         = "(userAccountControl:1.2.840.113556.1.4.803:=65536)"
	FilterMnsLogonAccount            = "(userAccountControl:1.2.840.113556.1.4.803:=131072)"
	FilterSmartCardRequired          = "(userAccountControl:1.2.840.113556.1.4.803:=262144)"
	FilterTrustedForDelegation       = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
	FilterNotDelegated               = "(userAccountControl:1.2.840.113556.1.4.803:=1048576)"
	FilterUseDesKeyOnly              = "(userAccountControl:1.2.840.113556.1.4.803:=2097152)"
	FilterDontRequirePreauth         = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
	FilterPasswordExpired            = "(userAccountControl:1.2.840.113556.1.4.803:=8388608)"
	FilterTrustedToAuthForDelegation = "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
	FilterPartialSecretsAccount      = "(userAccountControl:1.2.840.113556.1.4.803:=67108864)"
)

var ldapFilterConstants = map[string]string{
	"FilterIsPerson":                   FilterIsPerson,
	"FilterIsGroup":                    FilterIsGroup,
	"FilterIsComputer":                 FilterIsComputer,
	"FilterIsAdmin":                    FilterIsAdmin,
	"FilterHasServicePrincipalName":    FilterHasServicePrincipalName,
	"FilterLogonScript":                FilterLogonScript,
	"FilterAccountDisabled":            FilterAccountDisabled,
	"FilterAccountEnabled":             FilterAccountEnabled,
	"FilterHomedirRequired":            FilterHomedirRequired,
	"FilterLockout":                    FilterLockout,
	"FilterPasswordNotRequired":        FilterPasswordNotRequired,
	"FilterPasswordCantChange":         FilterPasswordCantChange,
	"FilterCanSendEncryptedPassword":   FilterCanSendEncryptedPassword,
	"FilterIsDuplicateAccount":         FilterIsDuplicateAccount,
	"FilterIsNormalAccount":            FilterIsNormalAccount,
	"FilterInterdomainTrustAccount":    FilterInterdomainTrustAccount,
	"FilterWorkstationTrustAccount":    FilterWorkstationTrustAccount,
	"FilterServerTrustAccount":         FilterServerTrustAccount,
	"FilterDontExpirePassword":         FilterDontExpirePassword,
	"FilterMnsLogonAccount":            FilterMnsLogonAccount,
	"FilterSmartCardRequired":          FilterSmartCardRequired,
	"FilterTrustedForDelegation":       FilterTrustedForDelegation,
	"FilterNotDelegated":               FilterNotDelegated,
	"FilterUseDesKeyOnly":              FilterUseDesKeyOnly,
	"FilterDontRequirePreauth":         FilterDontRequirePreauth,
	"FilterPasswordExpired":            FilterPasswordExpired,
	"FilterTrustedToAuthForDelegation": FilterTrustedToAuthForDelegation,
	"FilterPartialSecretsAccount":      FilterPartialSecretsAccount,
}

// JoinFilters AND-joins multiple LDAP filter strings — matches nuclei/ldap.JoinFilters.
func JoinFilters(filters ...string) string {
	var b strings.Builder
	b.WriteString("(&")
	for _, f := range filters {
		b.WriteString(f)
	}
	b.WriteString(")")
	return b.String()
}

// NegativeFilter wraps a filter in a NOT — matches nuclei/ldap.NegativeFilter.
func NegativeFilter(filter string) string {
	return fmt.Sprintf("(!%s)", filter)
}

// FindADObjects is the shared AD enumeration primitive every GetAD* helper
// below builds on — matches nuclei/ldap.Client.FindADObjects. This is the
// "account enumeration" functionality this session's project plan calls
// for: once a credential has authenticated (Authenticate /
// AuthenticateWithNTLMHash), these queries list the real accounts, groups
// and attack-relevant flags (kerberoastable, AS-REP roastable, never-expiring
// passwords, ...) an nxc-style operator would otherwise run GetADUsers /
// GetADAdmins / GetADUserKerberoastable etc. for by hand.
func (c *LDAPClient) FindADObjects(filter string) (*SearchResult, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("no existing connection")
	}
	res, err := c.conn.Search(ldap.NewSearchRequest(
		c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"distinguishedName", "sAMAccountName", "pwdLastSet", "lastLogon", "memberOf", "servicePrincipalName"},
		nil,
	))
	if err != nil {
		return nil, err
	}
	return getSearchResult(res), nil
}

func (c *LDAPClient) GetADUsers() (*SearchResult, error) { return c.FindADObjects(FilterIsPerson) }

func (c *LDAPClient) GetADActiveUsers() (*SearchResult, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled))
}

func (c *LDAPClient) GetADUserWithNeverExpiringPasswords() (*SearchResult, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterDontExpirePassword))
}

func (c *LDAPClient) GetADUserTrustedForDelegation() (*SearchResult, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterTrustedForDelegation))
}

func (c *LDAPClient) GetADUserWithPasswordNotRequired() (*SearchResult, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterPasswordNotRequired))
}

func (c *LDAPClient) GetADGroups() (*SearchResult, error) { return c.FindADObjects(FilterIsGroup) }

func (c *LDAPClient) GetADDCList() (*SearchResult, error) {
	return c.FindADObjects(JoinFilters(FilterIsComputer, FilterAccountEnabled, FilterServerTrustAccount))
}

func (c *LDAPClient) GetADAdmins() (*SearchResult, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled, FilterIsAdmin))
}

func (c *LDAPClient) GetADUserKerberoastable() (*SearchResult, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled, FilterHasServicePrincipalName))
}

func (c *LDAPClient) GetADUserAsRepRoastable() (*SearchResult, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterDontRequirePreauth))
}

// GetADDomainSID returns the domain's SID, read off a domain controller
// computer object's objectSid attribute — matches nuclei/ldap.Client.GetADDomainSID.
func (c *LDAPClient) GetADDomainSID() (string, error) {
	r, err := c.Search(FilterServerTrustAccount, "objectSid")
	if err != nil {
		return "", err
	}
	if len(r.Entries) == 0 {
		return "", fmt.Errorf("no result from GetADDomainSID query")
	}
	for _, entry := range r.Entries {
		if sid, ok := entry.Attributes.Extra["objectSid"]; ok {
			if sidList, ok := sid.([]string); ok && len(sidList) > 0 {
				return DecodeSID(sidList[0]), nil
			}
			return "", fmt.Errorf("invalid objectSid type: %T", sid)
		}
	}
	return "", fmt.Errorf("no objectSid found")
}
