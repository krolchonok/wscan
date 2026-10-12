package adscan

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"wscan/internal/domain"
)

// AccessOptions is a single explicitly chosen action against one controller.
// Directory inspection never requests tickets, triggers RPC or changes AD.
type AccessOptions struct {
	Host, Domain, Mode string
	LDAPPort           int
	Credential         domain.Credential
	ExportDir          string
	MaxObjects         int
}

type AccessCheck struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	State    string `json:"state"` // confirmed, candidate, observed, negative, denied, error, incomplete
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
}
type AccessObject struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}
type AccessReport struct {
	Host      string         `json:"host"`
	Mode      string         `json:"mode"`
	Checks    []AccessCheck  `json:"checks"`
	Objects   []AccessObject `json:"objects,omitempty"`
	Artifacts []string       `json:"artifacts,omitempty"`
}

func (r *AccessReport) add(id, name, state, severity, evidence string) {
	r.Checks = append(r.Checks, AccessCheck{id, name, state, severity, evidence})
}
func (r AccessReport) Findings() []domain.Finding {
	out := make([]domain.Finding, 0, len(r.Checks))
	for _, c := range r.Checks {
		severity := c.Severity
		if severity == "" {
			severity = "info"
		}
		out = append(out, domain.Finding{TemplateID: "ad-access/" + c.ID, Name: c.Name, Severity: severity,
			Target: r.Host, MatchedAt: "ad://" + r.Host + "/" + c.ID, Protocol: "ad", MatcherName: c.State,
			Evidence: "[" + c.State + "] " + c.Evidence, Risk: "Статус относится только к выполненной проверке; наличие предпосылки не доказывает получение доступа.", Time: time.Now().UTC()})
	}
	return out
}

func validateAccess(o *AccessOptions) error {
	o.Host = strings.TrimSpace(o.Host)
	o.Domain = strings.TrimSpace(o.Domain)
	if o.Host == "" || strings.ContainsAny(o.Host, "/\\ \t\r\n") {
		return fmt.Errorf("укажи один IP или DNS-хост контроллера")
	}
	if _, _, e := net.SplitHostPort(o.Host); e == nil {
		return fmt.Errorf("хост указывается без порта")
	}
	if o.Domain == "" || strings.ContainsAny(o.Domain, "/\\ \t\r\n@$") {
		return fmt.Errorf("укажи DNS-имя домена")
	}
	if o.LDAPPort == 0 {
		o.LDAPPort = 636
	}
	if o.LDAPPort != 389 && o.LDAPPort != 636 {
		return fmt.Errorf("LDAP-порт: 389 или 636")
	}
	if o.MaxObjects == 0 {
		o.MaxObjects = 5000
	}
	if o.MaxObjects < 1 || o.MaxObjects > 50000 {
		return fmt.Errorf("лимит LDAP: 1–50000")
	}
	if o.Credential.Username != "" && o.Credential.Type != "password" && o.Credential.Type != "ntlm-hash" {
		return fmt.Errorf("требуется пароль или NTLM-хеш")
	}
	if o.Credential.Type == "ntlm-hash" {
		b, e := hex.DecodeString(o.Credential.Secret)
		if e != nil || len(b) != 16 {
			return fmt.Errorf("NTLM-хеш должен содержать 16 байт")
		}
	}
	return nil
}

func RunAccess(ctx context.Context, o AccessOptions) (AccessReport, error) {
	r := AccessReport{Host: o.Host, Mode: o.Mode}
	if err := validateAccess(&o); err != nil {
		return r, err
	}
	switch o.Mode {
	case "directory":
		return directoryAccess(ctx, o)
	case "secrets":
		return r, fmt.Errorf("экспорт LAPS/gMSA секретов не включён; используй LDAP-аудит доступности атрибутов")
	case "spray":
		return r, fmt.Errorf("password spray не включён: он может блокировать учётные записи")
	case "ldap-security":
		return ldapSecurity(ctx, o)
	case "asrep":
		return kerberosAccess(ctx, o)
	case "user-enum", "kerberoast", "pre2k":
		return r, fmt.Errorf("этот Kerberos-режим отключён; смотри read-only кандидаты в LDAP-аудите")
	case "sysvol":
		return sysvolAccess(ctx, o)
	case "coercion":
		return r, fmt.Errorf("для Coerce используй RunCoercion с адресом локального приёмника и списком машин")
	default:
		return r, fmt.Errorf("неизвестное AD-действие %q", o.Mode)
	}
}

func accessLDAP(ctx context.Context, o AccessOptions, port int, bind bool) (*ldap.Conn, func(), error) {
	scheme := "ldap"
	if port == 636 {
		scheme = "ldaps"
	}
	c, e := ldap.DialURL(scheme+"://"+net.JoinHostPort(o.Host, strconv.Itoa(port)), ldap.DialWithDialer(&net.Dialer{Timeout: 4 * time.Second}),
		ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true})) // Same private-PKI policy as the existing LDAP client.
	if e != nil {
		return nil, nil, e
	}
	c.SetTimeout(8 * time.Second)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	closeFn := func() { stop(); c.Close() }
	if ctx.Err() != nil {
		closeFn()
		return nil, nil, ctx.Err()
	}
	if bind && o.Credential.Username != "" {
		cred := o.Credential
		realm := cred.Domain
		if realm == "" {
			realm = o.Domain
		}
		// One authentication mechanism, no fallback password attempts or anonymous bind.
		if cred.Type == "ntlm-hash" {
			e = c.NTLMBindWithHash(realm, cred.Username, cred.Secret)
		} else {
			e = c.NTLMBind(realm, cred.Username, cred.Secret)
		}
		if e != nil {
			closeFn()
			return nil, nil, e
		}
	}
	return c, closeFn, nil
}

func accessErrorState(e error) string {
	if ldap.IsErrorWithCode(e, ldap.LDAPResultInsufficientAccessRights) || ldap.IsErrorWithCode(e, ldap.LDAPResultInvalidCredentials) || ldap.IsErrorWithCode(e, ldap.LDAPResultStrongAuthRequired) {
		return "denied"
	}
	return "error"
}
func baseDN(domain string) string { return "DC=" + strings.Join(strings.Split(domain, "."), ",DC=") }

// Paged searches are capped and distinguish partial replies from empty success.
func accessSearch(ctx context.Context, c *ldap.Conn, base, filter string, attrs []string, limit int) ([]*ldap.Entry, error) {
	var out []*ldap.Entry
	page := ldap.NewControlPaging(uint32(min(500, limit)))
	seen := map[string]bool{}
	for {
		if e := ctx.Err(); e != nil {
			return out, e
		}
		controls := []ldap.Control{page}
		for _, a := range attrs {
			if strings.EqualFold(a, "nTSecurityDescriptor") {
				controls = append(controls, &ldap.ControlMicrosoftSDFlags{ControlValue: 4})
			}
		}
		req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 8, false, filter, attrs, controls)
		res, e := c.Search(req)
		truncated := false
		if res != nil {
			remaining := limit - len(out)
			truncated = len(res.Entries) > remaining
			out = append(out, res.Entries[:min(len(res.Entries), remaining)]...)
		}
		if e != nil {
			return out, e
		}
		if res == nil {
			return out, fmt.Errorf("LDAP вернул пустой ответ")
		}
		ctl, _ := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if ctl == nil || len(ctl.Cookie) == 0 {
			if truncated {
				return out, fmt.Errorf("лимит %d записей достигнут", limit)
			}
			return out, nil
		}
		if len(out) >= limit {
			return out, fmt.Errorf("лимит %d записей достигнут", limit)
		}
		cookie := string(ctl.Cookie)
		if seen[cookie] {
			return out, fmt.Errorf("LDAP повторил cookie пагинации")
		}
		seen[cookie] = true
		page.SetCookie(ctl.Cookie)
	}
}

func directoryAccess(ctx context.Context, o AccessOptions) (AccessReport, error) {
	r := AccessReport{Host: o.Host, Mode: o.Mode}
	c, closeFn, e := accessLDAP(ctx, o, o.LDAPPort, true)
	if e != nil {
		return r, e
	}
	defer closeFn()
	base := baseDN(o.Domain)
	queries := []struct {
		id, name, base, filter string
		attrs                  []string
	}{
		{"users", "Пользователи", base, "(&(objectCategory=person)(objectClass=user))", []string{"sAMAccountName", "userAccountControl", "servicePrincipalName", "pwdLastSet", "lastLogonTimestamp", "adminCount", "memberOf", "msDS-ResultantPSO"}},
		{"computers", "Компьютеры / pre2k", base, "(objectClass=computer)", []string{"sAMAccountName", "userAccountControl", "dNSHostName", "pwdLastSet", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity"}},
		{"policy", "Парольные политики", base, "(|(objectClass=domainDNS)(objectClass=msDS-PasswordSettings))", []string{"lockoutThreshold", "lockoutDuration", "lockOutObservationWindow", "minPwdLength", "pwdHistoryLength", "msDS-LockoutThreshold", "msDS-LockoutDuration", "msDS-LockoutObservationWindow", "msDS-MinimumPasswordLength", "msDS-PSOAppliesTo", "msDS-PasswordSettingsPrecedence"}},
		{"delegation", "Делегирование", base, "(|(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))", []string{"sAMAccountName", "userAccountControl", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity"}},
		{"trusts", "Доверия", base, "(objectClass=trustedDomain)", []string{"trustPartner", "trustDirection", "trustType", "trustAttributes"}},
		{"laps", "LAPS / Windows LAPS: читаемые атрибуты", base, "(objectClass=computer)", []string{"sAMAccountName", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"}},
		{"gmsa", "gMSA: читаемый managed password", base, "(objectClass=msDS-GroupManagedServiceAccount)", []string{"sAMAccountName", "msDS-ManagedPassword", "msDS-GroupMSAMembership"}},
	}
	for _, q := range queries {
		entries, err := accessSearch(ctx, c, q.base, q.filter, q.attrs, o.MaxObjects)
		state := "observed"
		detail := fmt.Sprintf("LDAP вернул %d объектов", len(entries))
		if err != nil {
			state = accessErrorState(err)
			if len(entries) > 0 {
				state = "incomplete"
			}
			detail += "; " + err.Error()
		}
		r.add(q.id, q.name, state, "info", detail)
		for _, entry := range entries {
			obj := AccessObject{DN: entry.DN, Attributes: map[string][]string{}}
			name := entry.GetAttributeValue("sAMAccountName")
			uac, _ := strconv.ParseUint(entry.GetAttributeValue("userAccountControl"), 10, 32)
			for _, a := range entry.Attributes {
				lower := strings.ToLower(a.Name)
				switch lower {
				case "ms-mcs-admpwd", "mslaps-password", "msds-managedpassword":
					if len(a.ByteValues) > 0 && len(a.ByteValues[0]) > 0 {
						obj.Attributes[a.Name] = []string{"[секрет доступен; значение скрыто]"}
						r.add(q.id+"-readable/"+name, q.name+": "+name, "confirmed", "high", "Выбранной учётке доступен секретный атрибут "+a.Name+"; значение не сохраняется в находках")
					}
				case "mslaps-encryptedpassword", "msds-groupmsamembership", "msds-allowedtoactonbehalfofotheridentity":
					obj.Attributes[a.Name] = []string{fmt.Sprintf("[бинарный атрибут: %d байт; эффективные права не рассчитаны]", len(entry.GetRawAttributeValue(a.Name)))}
				default:
					obj.Attributes[a.Name] = a.Values
				}
			}
			r.Objects = append(r.Objects, obj)
			if q.id == "users" && uac&2 == 0 {
				if uac&0x400000 != 0 {
					r.add("asrep-candidate/"+name, "AS-REP: "+name, "candidate", "medium", "LDAP DONT_REQ_PREAUTH; AS-REQ не отправлялся")
				}
				if len(entry.GetAttributeValues("servicePrincipalName")) > 0 {
					r.add("spn-candidate/"+name, "SPN: "+name, "candidate", "info", strings.Join(entry.GetAttributeValues("servicePrincipalName"), ", "))
				}
				if uac&32 != 0 {
					r.add("passwd-notreqd/"+name, "PASSWD_NOTREQD: "+name, "candidate", "low", "Флаг не доказывает пустой пароль")
				}
			}
			if q.id == "computers" && pre2kCandidate(uac) {
				r.add("pre2k-candidate/"+name, "pre2k: "+name, "candidate", "medium", "Компьютер WORKSTATION_TRUST_ACCOUNT + PASSWD_NOTREQD, включён; вход не проверялся")
			}
		}
	}
	auditADCS(ctx, c, o, &r)
	return r, ctx.Err()
}
func pre2kCandidate(uac uint64) bool { return uac&0x1000 != 0 && uac&32 != 0 && uac&2 == 0 }

func ldapSecurity(ctx context.Context, o AccessOptions) (AccessReport, error) {
	r := AccessReport{Host: o.Host, Mode: o.Mode}
	if o.Credential.Username == "" {
		return r, fmt.Errorf("для LDAP signing / CBT нужна известная рабочая учётка")
	}
	for _, port := range []int{389, 636} {
		c, closeFn, e := accessLDAP(ctx, o, port, true)
		id, name := "ldap-signing", "LDAP signing"
		if port == 636 {
			id, name = "ldap-cbt", "LDAPS channel binding"
		}
		if e == nil {
			closeFn()
			detail := "Сервер принял NTLM bind без LDAP signing на TCP/389"
			if port == 636 {
				detail = "Сервер принял NTLM bind без channel binding на TLS/636; это не проверка успешного relay"
			}
			r.add(id, name, "confirmed", "medium", detail)
		} else {
			state := accessErrorState(e)
			if ldap.IsErrorWithCode(e, ldap.LDAPResultStrongAuthRequired) {
				state = "negative"
			}
			r.add(id, name, state, "info", e.Error()+"; отказ не доказывает глобальную политику без проверки причины")
		}
		_ = c
	}
	return r, ctx.Err()
}

// Export is explicit. O_EXCL and 0600 avoid replacing existing sensitive files.
func writeAccessArtifact(dir, kind string, value any) (string, error) {
	if dir == "" {
		return "", errors.New("не указан каталог артефактов")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "ad-"+kind+"-*.json")
	if err != nil {
		return "", err
	}
	name, err := filepath.Abs(f.Name())
	if err == nil {
		err = f.Chmod(0600)
	}
	if err == nil {
		err = json.NewEncoder(f).Encode(value)
	}
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return name, nil
}
