package adscan

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"math"
	"strconv"
	"strings"
	"wscan/internal/domain"
)

var passwordPolicyAttributes = []string{
	"objectClass", "minPwdLength", "pwdHistoryLength", "minPwdAge", "maxPwdAge", "pwdProperties",
	"lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
	"msDS-MinimumPasswordLength", "msDS-PasswordHistoryLength", "msDS-MinimumPasswordAge", "msDS-MaximumPasswordAge",
	"msDS-PasswordComplexityEnabled", "msDS-PasswordReversibleEncryptionEnabled",
	"msDS-LockoutThreshold", "msDS-LockoutDuration", "msDS-LockoutObservationWindow", "msDS-PSOAppliesTo", "msDS-PasswordSettingsPrecedence",
}

func ParsePasswordPolicy(entry *ldap.Entry) domain.PasswordPolicy {
	p := domain.PasswordPolicy{DN: entry.DN, Source: "domain"}
	pso := false
	for _, v := range entry.GetEqualFoldAttributeValues("objectClass") {
		if strings.EqualFold(v, "msDS-PasswordSettings") {
			pso = true
		}
	}
	if pso {
		p.Source = "pso"
	}
	attr := func(a, b string) string {
		if pso {
			return b
		}
		return a
	}
	number := func(name string, interval bool) *int64 {
		vs := entry.GetEqualFoldAttributeValues(name)
		if len(vs) == 0 {
			p.MissingFields = append(p.MissingFields, name)
			return nil
		}
		if len(vs) != 1 {
			p.Errors = append(p.Errors, name+": multiple values")
			return nil
		}
		n, e := strconv.ParseInt(vs[0], 10, 64)
		if e != nil {
			p.Errors = append(p.Errors, name+": invalid integer")
			return nil
		}
		if interval {
			if n > 0 {
				p.Errors = append(p.Errors, name+": expected a non-positive AD interval")
				return nil
			}
			// Divide before negation, including the signed minimum sentinel.
			if n == math.MinInt64 {
				if name != "maxPwdAge" && name != "msDS-MaximumPasswordAge" {
					p.Errors = append(p.Errors, name+": invalid indefinite interval")
					return nil
				}
				n = 0
			} else {
				n = -(n / 10000000)
			}
		} else if n < 0 {
			p.Errors = append(p.Errors, name+": negative value")
			return nil
		}
		return &n
	}
	boolean := func(name string) *bool {
		vs := entry.GetEqualFoldAttributeValues(name)
		if len(vs) == 0 {
			p.MissingFields = append(p.MissingFields, name)
			return nil
		}
		if len(vs) != 1 {
			p.Errors = append(p.Errors, name+": multiple values")
			return nil
		}
		if !strings.EqualFold(vs[0], "TRUE") && !strings.EqualFold(vs[0], "FALSE") {
			p.Errors = append(p.Errors, name+": invalid boolean")
			return nil
		}
		b := strings.EqualFold(vs[0], "TRUE")
		return &b
	}
	p.MinLength = number(attr("minPwdLength", "msDS-MinimumPasswordLength"), false)
	p.HistoryLength = number(attr("pwdHistoryLength", "msDS-PasswordHistoryLength"), false)
	p.MinAgeSeconds = number(attr("minPwdAge", "msDS-MinimumPasswordAge"), true)
	p.MaxAgeSeconds = number(attr("maxPwdAge", "msDS-MaximumPasswordAge"), true)
	p.LockoutThreshold = number(attr("lockoutThreshold", "msDS-LockoutThreshold"), false)
	p.LockoutDurationSeconds = number(attr("lockoutDuration", "msDS-LockoutDuration"), true)
	p.ObservationWindowSeconds = number(attr("lockOutObservationWindow", "msDS-LockoutObservationWindow"), true)
	if pso {
		p.Complexity = boolean("msDS-PasswordComplexityEnabled")
		p.ReversibleEncryption = boolean("msDS-PasswordReversibleEncryptionEnabled")
		p.Precedence = number("msDS-PasswordSettingsPrecedence", false)
		p.AppliesTo = entry.GetEqualFoldAttributeValues("msDS-PSOAppliesTo")
	} else if flags := number("pwdProperties", false); flags != nil {
		complexity, reversible := *flags&1 != 0, *flags&16 != 0
		p.Complexity = &complexity
		p.ReversibleEncryption = &reversible
	}
	return p
}

func addPasswordPolicy(r *AccessReport, entry *ldap.Entry) {
	p := ParsePasswordPolicy(entry)
	r.Policies = append(r.Policies, p)
	state := "observed"
	if len(p.MissingFields)+len(p.Errors) > 0 {
		state = "incomplete"
	}
	b, _ := json.Marshal(p)
	r.add("passpolicy/"+entry.DN, "Парольная политика: "+entry.DN, state, "info", string(b))
	if p.Complexity != nil && !*p.Complexity {
		r.add("passpolicy-complexity/"+entry.DN, "Сложность паролей отключена", "confirmed", "medium", "Источник: "+entry.DN)
	}
	if p.ReversibleEncryption != nil && *p.ReversibleEncryption {
		r.add("passpolicy-reversible/"+entry.DN, "Обратимое хранение паролей разрешено", "confirmed", "high", "Источник: "+entry.DN)
	}
	if p.LockoutThreshold != nil && *p.LockoutThreshold == 0 {
		r.add("passpolicy-lockout/"+entry.DN, "Блокировка по числу ошибок отключена", "confirmed", "low", "Порог блокировки 0; остальные параметры блокировки не активируются. Это не разрешение на неограниченный перебор.")
	}
}

func passwordPolicyAccess(ctx context.Context, o AccessOptions) (AccessReport, error) {
	r := AccessReport{Host: o.Host, Mode: o.Mode}
	c, closeFn, e := accessLDAP(ctx, o, o.LDAPPort, true)
	if e != nil {
		return r, e
	}
	defer closeFn()
	// Read the naming context instead of treating an NTLM short domain as a DNS name.
	root, e := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 8, false, "(objectClass=*)", []string{"defaultNamingContext"}, nil))
	if e != nil {
		return r, e
	}
	if len(root.Entries) != 1 || root.Entries[0].GetAttributeValue("defaultNamingContext") == "" {
		return r, fmt.Errorf("LDAP не вернул defaultNamingContext")
	}
	entries, e := accessSearch(ctx, c, root.Entries[0].GetAttributeValue("defaultNamingContext"), "(|(objectClass=domainDNS)(objectClass=msDS-PasswordSettings))", passwordPolicyAttributes, o.MaxObjects)
	for _, entry := range entries {
		addPasswordPolicy(&r, entry)
	}
	if e != nil {
		r.add("passpolicy", "Чтение парольной политики", accessErrorState(e), "info", e.Error())
	}
	if e == nil && len(entries) == 0 {
		r.add("passpolicy", "Чтение парольной политики", "incomplete", "info", "Политики не возвращены; значения неизвестны")
	}
	return r, e
}
