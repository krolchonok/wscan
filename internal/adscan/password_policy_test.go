package adscan

import (
	"github.com/go-ldap/ldap/v3"
	"testing"
)

func TestPasswordPolicyDomainAndMissingValues(t *testing.T) {
	entry := ldap.NewEntry("DC=lab,DC=local", map[string][]string{
		"objectClass": {"domainDNS"}, "minPwdLength": {"7"}, "pwdHistoryLength": {"24"}, "minPwdAge": {"-864000000000"}, "maxPwdAge": {"-36288000000000"}, "pwdProperties": {"17"}, "lockoutThreshold": {"0"}, "lockoutDuration": {"-18000000000"}, "lockOutObservationWindow": {"-18000000000"},
	})
	p := ParsePasswordPolicy(entry)
	if p.Source != "domain" || *p.MinAgeSeconds != 86400 || *p.MaxAgeSeconds != 3628800 || *p.ObservationWindowSeconds != 1800 || !*p.Complexity || !*p.ReversibleEncryption || *p.LockoutThreshold != 0 || len(p.MissingFields) > 0 || len(p.Errors) > 0 {
		t.Fatalf("%+v", p)
	}
	missing := ParsePasswordPolicy(ldap.NewEntry("x", map[string][]string{"pwdProperties": {"0"}, "lockoutThreshold": {"broken"}}))
	if missing.MinLength != nil || missing.LockoutThreshold != nil || missing.Complexity == nil || *missing.Complexity || len(missing.MissingFields) == 0 || len(missing.Errors) == 0 {
		t.Fatalf("unknowns converted to defaults: %+v", missing)
	}
}
func TestPasswordPolicyPSOAndUnlimitedAge(t *testing.T) {
	p := ParsePasswordPolicy(ldap.NewEntry("CN=pso", map[string][]string{"objectClass": {"msDS-PasswordSettings"}, "msDS-MinimumPasswordLength": {"15"}, "msDS-PasswordComplexityEnabled": {"FALSE"}, "msDS-PasswordReversibleEncryptionEnabled": {"TRUE"}, "msDS-MaximumPasswordAge": {"-9223372036854775808"}, "msDS-PSOAppliesTo": {"CN=user"}, "msDS-PasswordSettingsPrecedence": {"1"}}))
	if p.Source != "pso" || *p.MinLength != 15 || *p.MaxAgeSeconds != 0 || *p.Complexity || !*p.ReversibleEncryption || len(p.AppliesTo) != 1 || *p.Precedence != 1 {
		t.Fatalf("%+v", p)
	}
}
