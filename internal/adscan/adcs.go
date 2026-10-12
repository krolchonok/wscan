package adscan

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func auditADCS(ctx context.Context, c *ldap.Conn, o AccessOptions, r *AccessReport) {
	root, e := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 8, false, "(objectClass=*)", []string{"configurationNamingContext"}, nil))
	if e != nil || root == nil || len(root.Entries) == 0 {
		r.add("adcs", "AD CS: конфигурация", "error", "info", "Не удалось прочитать configurationNamingContext")
		return
	}
	base := root.Entries[0].GetAttributeValue("configurationNamingContext")
	if base == "" {
		r.add("adcs", "AD CS: конфигурация", "error", "info", "configurationNamingContext отсутствует")
		return
	}
	cas, e := accessSearch(ctx, c, base, "(objectClass=pKIEnrollmentService)", []string{"cn", "dNSHostName", "certificateTemplates"}, o.MaxObjects)
	published := map[string][]string{}
	for _, ca := range cas {
		r.Objects = append(r.Objects, AccessObject{DN: ca.DN, Attributes: map[string][]string{"cn": ca.GetAttributeValues("cn"), "dNSHostName": ca.GetAttributeValues("dNSHostName"), "certificateTemplates": ca.GetAttributeValues("certificateTemplates")}})
		for _, name := range ca.GetAttributeValues("certificateTemplates") {
			published[strings.ToLower(name)] = append(published[strings.ToLower(name)], ca.GetAttributeValue("cn"))
		}
	}
	state := "observed"
	detail := fmt.Sprintf("Найдено CA: %d", len(cas))
	if e != nil {
		state = "incomplete"
		detail += "; " + e.Error()
	}
	r.add("adcs-ca", "AD CS: центры сертификации", state, "info", detail)
	templates, e := accessSearch(ctx, c, base, "(objectClass=pKICertificateTemplate)", []string{"cn", "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature", "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy", "nTSecurityDescriptor"}, o.MaxObjects)
	if e != nil {
		r.add("adcs-templates", "AD CS: шаблоны", "incomplete", "info", e.Error())
	}
	for _, t := range templates {
		name := t.GetAttributeValue("cn")
		ca := published[strings.ToLower(name)]
		nf, _ := strconv.ParseInt(t.GetAttributeValue("msPKI-Certificate-Name-Flag"), 10, 64)
		ef, _ := strconv.ParseInt(t.GetAttributeValue("msPKI-Enrollment-Flag"), 10, 64)
		sigText := t.GetAttributeValue("msPKI-RA-Signature")
		sig, err := strconv.ParseUint(sigText, 10, 32)
		eku := t.GetAttributeValues("pKIExtendedKeyUsage")
		app := t.GetAttributeValues("msPKI-Certificate-Application-Policy")
		obj := AccessObject{DN: t.DN, Attributes: map[string][]string{}}
		for _, a := range t.Attributes {
			if !strings.EqualFold(a.Name, "nTSecurityDescriptor") {
				obj.Attributes[a.Name] = a.Values
			}
		}
		grants, sdErr := broadADGrants(t.GetRawAttributeValue("nTSecurityDescriptor"))
		obj.Attributes["aclAssessment"] = []string{grants}
		r.Objects = append(r.Objects, obj)
		if len(ca) == 0 {
			continue
		}
		noApproval := ef&2 == 0 && err == nil && sig == 0
		anyPurpose := len(eku) == 0 || includes(eku, "2.5.29.37.0")
		clientAuth := anyPurpose || includes(eku, "1.3.6.1.5.5.7.3.2") || includes(eku, "1.3.6.1.4.1.311.20.2.2") || includes(eku, "1.3.6.1.5.2.3.4")
		evidence := fmt.Sprintf("Шаблон %s опубликован на %s; nameFlags=%d enrollmentFlags=%d RA-signatures=%s EKU=%v applicationPolicy=%v; %s. Эффективные права, deny ACE и ограничения CA требуют проверки", name, strings.Join(ca, ", "), nf, ef, sigText, eku, app, grants)
		if sdErr != nil {
			evidence += "; ACL: " + sdErr.Error()
		}
		if noApproval && clientAuth && nf&1 != 0 {
			r.add("esc1/"+name, "AD CS ESC1: "+name, "candidate", "medium", evidence)
		}
		if noApproval && anyPurpose {
			r.add("esc2/"+name, "AD CS ESC2: "+name, "candidate", "medium", evidence)
		}
		if noApproval && includes(eku, "1.3.6.1.4.1.311.20.2.1") {
			r.add("esc3/"+name, "AD CS ESC3: "+name, "candidate", "medium", evidence)
		}
		if ef&0x80000 != 0 {
			r.add("esc9/"+name, "AD CS ESC9: "+name, "candidate", "medium", evidence+"; эксплуатация зависит от certificate mapping / патчей DC")
		}
		if strings.Contains(grants, "write") {
			r.add("esc4/"+name, "AD CS ESC4: "+name, "candidate", "medium", evidence)
		}
	}
	r.add("adcs-limits", "AD CS: границы аудита", "observed", "info", "Читаются CA, публикация, флаги и ACL шаблонов. Сертификаты не запрашиваются; ESC6/7/8/10/11 и эффективный путь эксплуатации не подтверждаются LDAP-флагами")
}

func includes(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Parse only standard allow ACEs. This deliberately reports grants as
// candidates: a full Windows access check requires token, deny/inheritance and
// object-specific semantics. Malformed descriptors are never accepted.
func broadADGrants(sd []byte) (string, error) {
	if len(sd) < 20 {
		return "DACL недоступна", fmt.Errorf("нет полного security descriptor")
	}
	if binary.LittleEndian.Uint16(sd[2:4])&0x8000 == 0 {
		return "", fmt.Errorf("ожидался self-relative SD")
	}
	off := int(binary.LittleEndian.Uint32(sd[16:20]))
	if off == 0 {
		return "NULL DACL (требует отдельной проверки)", nil
	}
	if off > len(sd)-8 {
		return "", fmt.Errorf("ошибка смещения DACL")
	}
	acl := sd[off:]
	size := int(binary.LittleEndian.Uint16(acl[2:4]))
	count := int(binary.LittleEndian.Uint16(acl[4:6]))
	if size < 8 || size > len(acl) {
		return "", fmt.Errorf("ошибка длины DACL")
	}
	acl = acl[:size]
	var grants []string
	pos := 8
	for i := 0; i < count; i++ {
		if pos > len(acl)-4 {
			return "", fmt.Errorf("обрезанная ACE")
		}
		aceSize := int(binary.LittleEndian.Uint16(acl[pos+2 : pos+4]))
		if aceSize < 4 || aceSize > len(acl)-pos {
			return "", fmt.Errorf("ошибка длины ACE")
		}
		a := acl[pos : pos+aceSize]
		pos += aceSize
		if a[0] != 0 && a[0] != 5 {
			continue
		}
		if len(a) < 8 {
			return "", fmt.Errorf("обрезанная allow ACE")
		}
		if a[1]&8 != 0 {
			continue
		} // INHERIT_ONLY
		mask := binary.LittleEndian.Uint32(a[4:8])
		sidOff := 8
		if a[0] == 5 {
			if len(a) < 12 {
				return "", fmt.Errorf("обрезанная object ACE")
			}
			flags := binary.LittleEndian.Uint32(a[8:12])
			sidOff = 12
			if flags&1 != 0 {
				sidOff += 16
			}
			if flags&2 != 0 {
				sidOff += 16
			}
		}
		if sidOff > len(a)-8 {
			return "", fmt.Errorf("обрезанный SID")
		}
		sid, e := accessSID(a[sidOff:])
		if e != nil {
			return "", e
		}
		if sid != "S-1-1-0" && sid != "S-1-5-11" && !strings.HasSuffix(sid, "-513") && !strings.HasSuffix(sid, "-515") {
			continue
		}
		rights := ""
		if mask&(0x10000000|0x40000000|0x40000|0x80000|0x20) != 0 {
			rights += "write "
		}
		if mask&0x100 != 0 {
			rights += "extended-right "
		}
		if rights != "" {
			grants = append(grants, fmt.Sprintf("%s %s(mask=0x%x)", sid, rights, mask))
		}
	}
	if len(grants) == 0 {
		return "Широкие allow ACE не найдены; эффективные права не рассчитаны", nil
	}
	return strings.Join(grants, "; "), nil
}
func accessSID(b []byte) (string, error) {
	if len(b) < 8 || b[0] != 1 || int(b[1]) > 15 || len(b) < 8+4*int(b[1]) {
		return "", fmt.Errorf("ошибка SID")
	}
	var auth uint64
	for _, v := range b[2:8] {
		auth = auth<<8 | uint64(v)
	}
	s := fmt.Sprintf("S-1-%d", auth)
	for i := 0; i < int(b[1]); i++ {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return s, nil
}
