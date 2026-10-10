package js

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// SearchResult / LdapEntry / LdapAttributes mirror nuclei/ldap's shapes
// field-for-field (json tags required — see LDAPClient's doc comment).
type SearchResult struct {
	Referrals []string    `json:"referrals"`
	Controls  []string    `json:"controls"`
	Entries   []LdapEntry `json:"entries"`
}

type LdapEntry struct {
	DN         string         `json:"dn"`
	Attributes LdapAttributes `json:"attributes"`
}

type LdapAttributes struct {
	CurrentTime                   []string       `json:"currentTime,omitempty"`
	SubschemaSubentry             []string       `json:"subschemaSubentry,omitempty"`
	DsServiceName                 []string       `json:"dsServiceName,omitempty"`
	NamingContexts                []string       `json:"namingContexts,omitempty"`
	DefaultNamingContext          []string       `json:"defaultNamingContext,omitempty"`
	SchemaNamingContext           []string       `json:"schemaNamingContext,omitempty"`
	ConfigurationNamingContext    []string       `json:"configurationNamingContext,omitempty"`
	RootDomainNamingContext       []string       `json:"rootDomainNamingContext,omitempty"`
	SupportedLDAPVersion          []string       `json:"supportedLDAPVersion,omitempty"`
	HighestCommittedUSN           []string       `json:"highestCommittedUSN,omitempty"`
	SupportedSASLMechanisms       []string       `json:"supportedSASLMechanisms,omitempty"`
	DnsHostName                   []string       `json:"dnsHostName,omitempty"`
	LdapServiceName               []string       `json:"ldapServiceName,omitempty"`
	ServerName                    []string       `json:"serverName,omitempty"`
	IsSynchronized                []string       `json:"isSynchronized,omitempty"`
	IsGlobalCatalogReady          []string       `json:"isGlobalCatalogReady,omitempty"`
	DomainFunctionality           []string       `json:"domainFunctionality,omitempty"`
	ForestFunctionality           []string       `json:"forestFunctionality,omitempty"`
	DomainControllerFunctionality []string       `json:"domainControllerFunctionality,omitempty"`
	DistinguishedName             []string       `json:"distinguishedName,omitempty"`
	SAMAccountName                []string       `json:"sAMAccountName,omitempty"`
	PWDLastSet                    []string       `json:"pwdLastSet,omitempty"`
	LastLogon                     []string       `json:"lastLogon,omitempty"`
	MemberOf                      []string       `json:"memberOf,omitempty"`
	ServicePrincipalName          []string       `json:"servicePrincipalName,omitempty"`
	Extra                         map[string]any `json:"extra,omitempty"`
}

func getSearchResult(sr *ldap.SearchResult) *SearchResult {
	t := &SearchResult{Referrals: []string{}, Controls: []string{}, Entries: []LdapEntry{}}
	t.Referrals = append(t.Referrals, sr.Referrals...)
	for _, ctrl := range sr.Controls {
		t.Controls = append(t.Controls, ctrl.String())
	}
	for _, entry := range sr.Entries {
		t.Entries = append(t.Entries, parseLdapEntry(entry))
	}
	return t
}

func parseLdapEntry(entry *ldap.Entry) LdapEntry {
	e := LdapEntry{DN: entry.DN}
	attrs := LdapAttributes{Extra: make(map[string]any)}
	for _, attr := range entry.Attributes {
		switch attr.Name {
		case "currentTime":
			attrs.CurrentTime = decodeTimestamps(attr.Values)
		case "subschemaSubentry":
			attrs.SubschemaSubentry = attr.Values
		case "dsServiceName":
			attrs.DsServiceName = attr.Values
		case "namingContexts":
			attrs.NamingContexts = attr.Values
		case "defaultNamingContext":
			attrs.DefaultNamingContext = attr.Values
		case "schemaNamingContext":
			attrs.SchemaNamingContext = attr.Values
		case "configurationNamingContext":
			attrs.ConfigurationNamingContext = attr.Values
		case "rootDomainNamingContext":
			attrs.RootDomainNamingContext = attr.Values
		case "supportedLDAPVersion":
			attrs.SupportedLDAPVersion = attr.Values
		case "highestCommittedUSN":
			attrs.HighestCommittedUSN = attr.Values
		case "supportedSASLMechanisms":
			attrs.SupportedSASLMechanisms = attr.Values
		case "dnsHostName":
			attrs.DnsHostName = attr.Values
		case "ldapServiceName":
			attrs.LdapServiceName = attr.Values
		case "serverName":
			attrs.ServerName = attr.Values
		case "isSynchronized":
			attrs.IsSynchronized = attr.Values
		case "isGlobalCatalogReady":
			attrs.IsGlobalCatalogReady = attr.Values
		case "domainFunctionality":
			attrs.DomainFunctionality = attr.Values
		case "forestFunctionality":
			attrs.ForestFunctionality = attr.Values
		case "domainControllerFunctionality":
			attrs.DomainControllerFunctionality = attr.Values
		case "distinguishedName":
			attrs.DistinguishedName = attr.Values
		case "sAMAccountName":
			attrs.SAMAccountName = attr.Values
		case "pwdLastSet":
			attrs.PWDLastSet = decodeTimestamps(attr.Values)
		case "lastLogon":
			attrs.LastLogon = decodeTimestamps(attr.Values)
		case "memberOf":
			attrs.MemberOf = attr.Values
		case "servicePrincipalName":
			attrs.ServicePrincipalName = attr.Values
		default:
			attrs.Extra[attr.Name] = attr.Values
		}
	}
	e.Attributes = attrs
	return e
}

func decodeTimestamps(timestamps []string) []string {
	res := []string{}
	for _, t := range timestamps {
		res = append(res, DecodeADTimestamp(t))
	}
	return res
}

// DecodeSID decodes a raw (binary-as-string) Windows SID into its canonical
// "S-1-5-..." form — matches nuclei/ldap.DecodeSID exactly.
func DecodeSID(s string) string {
	b := []byte(s)
	if len(b) < 8 {
		return ""
	}
	revisionLvl := int(b[0])
	subAuthorityCount := int(b[1]) & 0xFF

	var authority int
	for i := 2; i <= 7; i++ {
		authority = authority | int(b[i])<<(8*(5-(i-2)))
	}

	const size = 4
	offset := 8
	var subAuthorities []int
	for i := 0; i < subAuthorityCount && offset+size <= len(b); i++ {
		var subAuthority int
		for k := 0; k < size; k++ {
			subAuthority = subAuthority | (int(b[offset+k])&0xFF)<<(8*k)
		}
		subAuthorities = append(subAuthorities, subAuthority)
		offset += size
	}

	var builder strings.Builder
	builder.WriteString("S-")
	fmt.Fprintf(&builder, "%d-", revisionLvl)
	fmt.Fprintf(&builder, "%d", authority)
	for _, v := range subAuthorities {
		fmt.Fprintf(&builder, "-%d", v)
	}
	return builder.String()
}

// DecodeADTimestamp decodes an Active Directory FILETIME-as-decimal-string
// timestamp (e.g. pwdLastSet, lastLogon) — matches nuclei/ldap.DecodeADTimestamp.
func DecodeADTimestamp(timestamp string) string {
	adtime, _ := strconv.ParseInt(timestamp, 10, 64)
	if adtime == 9223372036854775807 || adtime == 0 {
		return "Not Set"
	}
	unixtimeInt64 := adtime/(10*1000*1000) - 11644473600
	return time.Unix(unixtimeInt64, 0).Format("2006-01-02 3:4:5 pm")
}

// DecodeZuluTimestamp decodes an RFC3339 ("Zulu") timestamp into the same
// display format as DecodeADTimestamp — matches nuclei/ldap.DecodeZuluTimestamp.
func DecodeZuluTimestamp(timestamp string) string {
	zulu, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return ""
	}
	return zulu.Format("2006-01-02 3:4:5 pm")
}
