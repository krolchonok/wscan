package adscan

import (
	"sort"
	"strings"
)

// Conservative built-in principals give black-box reconnaissance a useful
// Kerberos identity baseline when anonymous LDAP and SAMR are unavailable.
// They are usernames only: no password or authentication attempt is made.
var kerberosBaselineUsers = []string{"administrator", "guest", "krbtgt"}

// ASREPReconOptions groups collected names by realm and chooses one discovered
// KDC per realm. DNS records never introduce hosts outside the selected scope.
// Missing identities/names are explicit skips, never a negative vulnerability result.
func ASREPReconOptions(result Result) ([]AccessOptions, []string) {
	type realmData struct{ hosts, users []string }
	groups := map[string]*realmData{}
	for _, host := range result.Hosts {
		realm := strings.TrimSuffix(strings.ToLower(host.Domain), ".")
		if realm == "" {
			continue
		}
		if groups[realm] == nil {
			groups[realm] = &realmData{}
		}
		group := groups[realm]
		group.users = append(group.users, host.LDAPUsers...)
		group.users = append(group.users, host.SMBUsers...)
		group.users = append(group.users, host.ASREPUsers...)
		if contains(host.Ports, 88) {
			group.hosts = append(group.hosts, host.Address)
		}
	}
	var realms []string
	for realm := range groups {
		realms = append(realms, realm)
	}
	sort.Strings(realms)
	var out []AccessOptions
	var skipped []string
	if len(realms) == 0 {
		skipped = append(skipped, "AS-REP пропущен: домен не обнаружен.")
	}
	for _, realm := range realms {
		group := groups[realm]
		group.hosts = uniqueSorted(group.hosts)
		group.users = append(group.users, kerberosBaselineUsers...)
		group.users = uniqueSorted(group.users)
		if len(group.hosts) == 0 {
			skipped = append(skipped, "AS-REP пропущен: "+realm+" — в области нет обнаруженного KDC TCP/88.")
			continue
		}
		out = append(out, AccessOptions{Mode: "asrep", Host: group.hosts[0], Domain: realm, Users: group.users, MaxObjects: 5000})
	}
	return out, skipped
}
