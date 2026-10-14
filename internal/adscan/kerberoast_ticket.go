package adscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

type roastSession struct {
	User, Realm string
	Ticket      messages.Ticket
	Key         types.EncryptionKey
	Start, End  time.Time
	Flags       asn1.BitString
}

func validateRoastSession(s roastSession, realm string) error {
	if !strings.EqualFold(s.Realm, realm) || !strings.EqualFold(s.Ticket.Realm, realm) || s.Ticket.TktVNO != 5 || len(s.Ticket.SName.NameString) != 2 || !strings.EqualFold(s.Ticket.SName.NameString[0], "krbtgt") || !strings.EqualFold(s.Ticket.SName.NameString[1], realm) || len(s.Ticket.EncPart.Cipher) == 0 {
		return fmt.Errorf("нужен локальный TGT krbtgt/%s для выбранного домена; service/referral билеты не подходят", strings.ToUpper(realm))
	}
	if _, err := NormalizeASREPUsers([]string{s.User}, realm, 1); err != nil || s.User == "" {
		return fmt.Errorf("TGT: некорректный клиент")
	}
	etype, err := crypto.GetEtype(s.Key.KeyType)
	if err != nil || (s.Key.KeyType != 17 && s.Key.KeyType != 18 && s.Key.KeyType != 23) || len(s.Key.KeyValue) != etype.GetKeyByteSize() {
		return fmt.Errorf("TGT: нужен сеансовый ключ RC4/AES правильной длины")
	}
	now := time.Now()
	if s.End.IsZero() || !s.End.After(now) || (!s.Start.IsZero() && s.Start.After(now.Add(5*time.Minute))) || (len(s.Flags.Bytes) > 0 && types.IsFlagSet(&s.Flags, flags.Invalid)) {
		return fmt.Errorf("TGT истёк, ещё не действует или помечен invalid")
	}
	return nil
}

// loadRoastSession reads only the explicit file; no OS cache, injection or
// renewal. .kirbi (unencrypted KRB-CRED) and ccache v3/v4 are supported.
func loadRoastSession(path, realm string) (session roastSession, err error) {
	// The upstream ASN.1 ticket-sequence decoder assumes complete headers.
	defer func() {
		if recover() != nil {
			session = roastSession{}
			err = fmt.Errorf("TGT: повреждённая ASN.1 структура")
		}
	}()
	b, err := readKerberosFile(path)
	if err != nil {
		return roastSession{}, err
	}
	var candidates []roastSession
	if len(b) >= 2 && b[0] == 5 {
		candidates, err = readRoastCCache(b)
	} else {
		var raw asn1.RawValue
		var rest []byte
		rest, err = asn1.Unmarshal(b, &raw)
		if err == nil && len(rest) != 0 {
			err = fmt.Errorf("лишние данные после KRB-CRED")
		}
		var cred messages.KRBCred
		if err == nil {
			err = cred.Unmarshal(b)
		}
		if err == nil && (cred.PVNO != 5 || cred.EncPart.EType != 0) {
			err = fmt.Errorf("нужен незашифрованный KRB-CRED (.kirbi) с сеансовым ключом")
		}
		if err == nil {
			err = cred.DecryptedEncPart.Unmarshal(cred.EncPart.Cipher)
		}
		if err == nil && len(cred.Tickets) != len(cred.DecryptedEncPart.TicketInfo) {
			err = fmt.Errorf("KRB-CRED: число билетов и ключей отличается")
		}
		if err == nil {
			for i, ticket := range cred.Tickets {
				info := cred.DecryptedEncPart.TicketInfo[i]
				if len(info.PName.NameString) != 1 || !ticket.SName.Equal(info.SName) || !strings.EqualFold(ticket.Realm, info.SRealm) {
					return roastSession{}, fmt.Errorf("KRB-CRED: метаданные билета не совпадают")
				}
				candidates = append(candidates, roastSession{User: info.PName.NameString[0], Realm: info.PRealm, Ticket: ticket, Key: info.Key, Start: info.StartTime, End: info.EndTime, Flags: info.Flags})
			}
		}
	}
	if err != nil {
		return roastSession{}, fmt.Errorf("TGT: файл повреждён или формат не поддерживается: %w", err)
	}
	var selected []roastSession
	for _, s := range candidates {
		if !strings.EqualFold(s.Realm, realm) || len(s.Ticket.SName.NameString) != 2 || !strings.EqualFold(s.Ticket.SName.NameString[0], "krbtgt") || !strings.EqualFold(s.Ticket.SName.NameString[1], realm) {
			continue
		}
		if err := validateRoastSession(s, realm); err != nil {
			return roastSession{}, err
		}
		selected = append(selected, s)
	}
	if len(selected) != 1 {
		return roastSession{}, fmt.Errorf("файл должен содержать ровно один действующий локальный TGT выбранного домена")
	}
	return selected[0], nil
}

// The upstream ccache parser allocates using file-controlled counts. Parse
// bounded v3/v4 fields here so malformed local files cannot panic or allocate
// unbounded arrays.
type roastCacheReader struct{ *bytes.Reader }

func (r roastCacheReader) number(size int) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:size]); err != nil {
		return 0, err
	}
	if size == 2 {
		return uint32(binary.BigEndian.Uint16(b[:2])), nil
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func (r roastCacheReader) data() ([]byte, error) {
	n, err := r.number(4)
	if err != nil || uint64(n) > uint64(r.Len()) {
		return nil, fmt.Errorf("ccache: обрезанное поле")
	}
	b := make([]byte, int(n))
	_, err = io.ReadFull(r, b)
	return b, err
}

func (r roastCacheReader) principal() (string, types.PrincipalName, error) {
	kind, err := r.number(4)
	if err != nil {
		return "", types.PrincipalName{}, err
	}
	n, err := r.number(4)
	if err != nil || n == 0 || n > 16 {
		return "", types.PrincipalName{}, fmt.Errorf("ccache: некорректный principal")
	}
	realm, err := r.data()
	if err != nil || len(realm) > 512 {
		return "", types.PrincipalName{}, fmt.Errorf("ccache: некорректный realm")
	}
	p := types.PrincipalName{NameType: int32(kind)}
	for i := uint32(0); i < n; i++ {
		value, err := r.data()
		if err != nil || len(value) == 0 || len(value) > 512 {
			return "", p, fmt.Errorf("ccache: некорректное имя")
		}
		p.NameString = append(p.NameString, string(value))
	}
	return string(realm), p, nil
}

func readRoastCCache(b []byte) ([]roastSession, error) {
	if len(b) < 2 || b[0] != 5 || (b[1] != 3 && b[1] != 4) {
		return nil, fmt.Errorf("поддерживаются ccache v3/v4")
	}
	r := roastCacheReader{bytes.NewReader(b[2:])}
	if b[1] == 4 {
		n, err := r.number(2)
		if err != nil || int(n) > r.Len() {
			return nil, fmt.Errorf("ccache: повреждён заголовок")
		}
		r.Seek(int64(n), io.SeekCurrent)
	}
	if _, _, err := r.principal(); err != nil {
		return nil, err
	}
	var sessions []roastSession
	for r.Len() > 0 {
		if len(sessions) >= 256 {
			return nil, fmt.Errorf("ccache: более 256 записей")
		}
		realm, client, err := r.principal()
		if err != nil || len(client.NameString) != 1 {
			return nil, fmt.Errorf("ccache: некорректный клиент")
		}
		serverRealm, server, err := r.principal()
		if err != nil {
			return nil, err
		}
		kt, err := r.number(2)
		if err != nil {
			return nil, err
		}
		if b[1] == 3 {
			if _, err := r.number(2); err != nil {
				return nil, err
			}
		}
		key, err := r.data()
		if err != nil {
			return nil, err
		}
		var times [4]uint32
		for i := range times {
			times[i], err = r.number(4)
			if err != nil {
				return nil, err
			}
		}
		if _, err := r.ReadByte(); err != nil {
			return nil, err
		}
		bits, err := r.number(4)
		if err != nil {
			return nil, err
		}
		for i := 0; i < 2; i++ { // addresses and authorization data
			n, err := r.number(4)
			if err != nil || n > 4096 {
				return nil, fmt.Errorf("ccache: некорректный список данных")
			}
			for j := uint32(0); j < n; j++ {
				if _, err := r.number(2); err != nil {
					return nil, err
				}
				if _, err := r.data(); err != nil {
					return nil, err
				}
			}
		}
		ticketBytes, err := r.data()
		if err != nil {
			return nil, err
		}
		if _, err := r.data(); err != nil { // second ticket
			return nil, err
		}
		// MIT cache configuration records do not contain actual tickets.
		if strings.HasPrefix(serverRealm, "X-CACHECONF:") {
			continue
		}
		var ticket messages.Ticket
		if err := ticket.Unmarshal(ticketBytes); err != nil {
			return nil, err
		}
		if !ticket.SName.Equal(server) || !strings.EqualFold(ticket.Realm, serverRealm) {
			return nil, fmt.Errorf("ccache: метаданные билета не совпадают")
		}
		f := types.NewKrbFlags()
		binary.BigEndian.PutUint32(f.Bytes, bits)
		sessions = append(sessions, roastSession{User: client.NameString[0], Realm: realm, Ticket: ticket, Key: types.EncryptionKey{KeyType: int32(kt), KeyValue: key}, Start: time.Unix(int64(times[1]), 0), End: time.Unix(int64(times[2]), 0), Flags: f})
	}
	return sessions, nil
}
