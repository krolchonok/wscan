package adscan

import (
	"context"
)

// kerberosAccess is deliberately a read-only LDAP inventory. It identifies
// DONT_REQ_PREAUTH candidates without sending AS-REQs or exporting tickets.
func kerberosAccess(ctx context.Context, o AccessOptions) (AccessReport, error) {
	r := AccessReport{Host: o.Host, Mode: o.Mode}
	c, closeFn, err := accessLDAP(ctx, o, o.LDAPPort, true)
	if err != nil {
		return r, err
	}
	defer closeFn()
	filter := "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	entries, err := accessSearch(ctx, c, baseDN(o.Domain), filter, []string{"sAMAccountName"}, o.MaxObjects)
	if err != nil {
		r.add("asrep", "AS-REP candidates", "incomplete", "info", err.Error())
	}
	for _, entry := range entries {
		name := entry.GetAttributeValue("sAMAccountName")
		r.add("asrep-candidate/"+name, "AS-REP candidate: "+name, "candidate", "medium", "LDAP DONT_REQ_PREAUTH flag; KDC was not queried and no ticket/hash was requested")
	}
	if len(entries) == 0 && err == nil {
		r.add("asrep", "AS-REP candidates", "negative", "info", "LDAP returned no enabled accounts with DONT_REQ_PREAUTH; KDC was not queried")
	}
	return r, ctx.Err()
}
