package adscan

// The collector only reads the selected DC. No code or files are sent to Windows.
import (
	"archive/zip"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// CE schema and method bits follow SpecterOps packages/go/chow/ingest and
// packages/go/ein/incoming_models.go. ACL and machine methods are not claimed.
const bloodHoundMethods = 1 | 32 | 128 | 512 // Group, Trusts, Container, ObjectProps

var bloodHoundTypes = []string{"users", "computers", "groups", "domains", "ous", "gpos", "containers"}

type BloodHoundOptions struct {
	AccessOptions
	Progress func(string)
}
type bhPrincipal struct {
	ObjectIdentifier string
	ObjectType       string
}
type bhNode map[string]any

type BloodHoundSummary struct {
	Format        string         `json:"format"`
	Domain        string         `json:"domain"`
	Controller    string         `json:"controller"`
	CollectedAt   time.Time      `json:"collected_at"`
	Counts        map[string]int `json:"counts"`
	Relationships int            `json:"relationships"`
	Partial       bool           `json:"partial"`
	Warnings      []string       `json:"warnings"`
	NotCollected  []string       `json:"not_collected"`
}
type bhGraph struct {
	nodes   map[string][]bhNode
	summary BloodHoundSummary
}
type bhSearcher interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

func RunBloodHound(ctx context.Context, o BloodHoundOptions) (AccessReport, error) {
	r := AccessReport{Host: o.Host, Mode: "bloodhound-ce"}
	if err := validateAccess(&o.AccessOptions); err != nil {
		return r, err
	}
	if o.Credential.Username == "" {
		return r, fmt.Errorf("BloodHound требует сохранённую доменную учётку с паролем или NTLM-хешем")
	}
	if o.ExportDir == "" {
		return r, fmt.Errorf("не задан каталог экспорта")
	}
	emit := o.Progress
	if emit == nil {
		emit = func(string) {}
	}
	emit(fmt.Sprintf("BloodHound CE: вход LDAP/%d на %s", o.LDAPPort, o.Host))
	c, closeFn, err := accessLDAP(ctx, o.AccessOptions, o.LDAPPort, true)
	if err != nil {
		return r, fmt.Errorf("BloodHound LDAP: %w", err)
	}
	defer closeFn()
	graph, err := collectBloodHound(ctx, c, o, emit)
	if err != nil {
		return r, err
	}
	if err = ctx.Err(); err != nil {
		return r, err
	}
	emit("BloodHound CE: запись ZIP")
	path, err := writeBloodHound(ctx, o.ExportDir, graph)
	if err != nil {
		return r, err
	}
	r.Artifacts = append(r.Artifacts, path, path+".summary.json")
	state := "observed"
	if graph.summary.Partial {
		state = "incomplete"
	}
	b, _ := json.MarshalIndent(graph.summary, "", "  ")
	r.add("bloodhound-ce", "BloodHound CE: удалённый сбор домена", state, "info", string(b)+"\nZIP: "+path)
	emit(fmt.Sprintf("BloodHound CE: %d объектов, %d связей; ZIP: %s", graph.total(), graph.summary.Relationships, path))
	return r, nil
}

var bhAttributes = []string{"objectClass", "objectSid", "objectGUID", "name", "displayName", "sAMAccountName", "dNSHostName", "description", "userAccountControl", "primaryGroupID", "member", "adminCount", "servicePrincipalName", "operatingSystem", "operatingSystemVersion", "pwdLastSet", "lastLogon", "lastLogonTimestamp", "whenCreated", "gPCFileSysPath", "gPLink", "gPOptions", "trustPartner", "trustDirection", "trustType", "trustAttributes", "securityIdentifier"}

func collectBloodHound(ctx context.Context, c bhSearcher, o BloodHoundOptions, emit func(string)) (bhGraph, error) {
	g := bhGraph{nodes: map[string][]bhNode{}, summary: BloodHoundSummary{Format: "BloodHound CE AD JSON v6", Domain: strings.ToUpper(o.Domain), Controller: o.Host, CollectedAt: time.Now().UTC(), Counts: map[string]int{}, Warnings: []string{}, NotCollected: []string{"ACL", "AD CS", "SYSVOL policy contents", "local groups", "user rights", "sessions", "remote registry", "resolved delegation and SID history"}}}
	for _, typ := range bloodHoundTypes {
		g.nodes[typ] = []bhNode{}
	}
	base := baseDN(o.Domain)
	root, err := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 8, false, "(objectClass=*)", []string{"defaultNamingContext"}, nil))
	if err != nil {
		return g, fmt.Errorf("RootDSE: %w", err)
	}
	if root == nil || len(root.Entries) != 1 || !strings.EqualFold(root.Entries[0].GetAttributeValue("defaultNamingContext"), base) {
		return g, fmt.Errorf("DC не подтвердил naming context выбранного домена %s", o.Domain)
	}
	// Read the domain root separately: subtree paging order is not guaranteed,
	// and a user-selected limit must not lose the domain SID.
	domainRoot, err := c.Search(ldap.NewSearchRequest(base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 8, false, "(objectClass=domainDNS)", bhAttributes, nil))
	if err != nil {
		return g, fmt.Errorf("объект домена: %w", err)
	}
	if domainRoot == nil || len(domainRoot.Entries) != 1 || !strings.EqualFold(domainRoot.Entries[0].DN, base) || bhSID(domainRoot.Entries[0].GetRawAttributeValue("objectSid")) == "" {
		return g, fmt.Errorf("не удалось прочитать SID объекта выбранного домена")
	}
	emit("BloodHound CE: объекты домена (LDAP, без обращения к компьютерам)")
	// Keep the search inside this naming context; referrals are not followed.
	entries, searchErr := bhPagedSearch(ctx, c, base, bhAttributes, o.MaxObjects)
	if ctx.Err() != nil {
		return g, ctx.Err()
	}
	if searchErr != nil {
		g.warn("LDAP: " + searchErr.Error())
	}
	if len(entries) == 0 && searchErr == nil {
		g.warn("LDAP-поиск не вернул объекты; прочитан только корень домена")
	}
	combined := []*ldap.Entry{domainRoot.Entries[0]}
	for _, entry := range entries {
		if strings.EqualFold(entry.DN, base) {
			continue
		}
		if len(combined) >= o.MaxObjects {
			g.warn(fmt.Sprintf("лимит %d объектов достигнут", o.MaxObjects))
			break
		}
		combined = append(combined, entry)
	}
	entries = combined
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return g, err
		}
		if bhKind(entry) == "Group" {
			if err := bhExpandMembers(ctx, c, entry, o.MaxObjects); err != nil {
				g.warn("Группа " + entry.DN + ": " + err.Error())
			}
		}
	}
	bhBuildGraph(entries, &g)
	if len(g.nodes["domains"]) != 1 {
		return g, fmt.Errorf("не удалось прочитать SID объекта выбранного домена; экспорт остановлен")
	}
	for _, typ := range bloodHoundTypes {
		g.summary.Counts[typ] = len(g.nodes[typ])
		emit(fmt.Sprintf("BloodHound CE: %s — %d", typ, len(g.nodes[typ])))
	}
	for _, warning := range g.summary.Warnings {
		emit("BloodHound CE: неполные данные: " + warning)
	}
	return g, nil
}
func (g *bhGraph) warn(s string) {
	g.summary.Partial = true
	if len(g.summary.Warnings) < 200 {
		g.summary.Warnings = append(g.summary.Warnings, s)
	} else if len(g.summary.Warnings) == 200 {
		g.summary.Warnings = append(g.summary.Warnings, "Дополнительные предупреждения скрыты (лимит 200)")
	}
}
func (g bhGraph) total() int {
	n := 0
	for _, nodes := range g.nodes {
		n += len(nodes)
	}
	return n
}

func bhPagedSearch(ctx context.Context, c bhSearcher, base string, attrs []string, limit int) ([]*ldap.Entry, error) {
	var out []*ldap.Entry
	page := ldap.NewControlPaging(uint32(min(500, limit)))
	seen := map[string]bool{}
	filter := "(|(objectClass=user)(objectClass=group)(objectClass=domainDNS)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)(objectClass=container)(objectClass=foreignSecurityPrincipal)(objectClass=trustedDomain))"
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		r, err := c.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 8, false, filter, attrs, []ldap.Control{page}))
		if r != nil {
			n := min(len(r.Entries), limit-len(out))
			out = append(out, r.Entries[:n]...)
			if n < len(r.Entries) && err == nil {
				err = fmt.Errorf("лимит %d объектов достигнут", limit)
			}
			if len(r.Referrals) > 0 && err == nil {
				err = fmt.Errorf("LDAP referrals не обработаны; сбор ограничен выбранным доменом")
			}
		}
		if err != nil {
			return out, err
		}
		if r == nil {
			return out, fmt.Errorf("пустой LDAP-ответ")
		}
		ctl, _ := ldap.FindControl(r.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if ctl == nil || len(ctl.Cookie) == 0 {
			return out, nil
		}
		if len(out) >= limit {
			return out, fmt.Errorf("лимит %d объектов достигнут", limit)
		}
		cookie := string(ctl.Cookie)
		if seen[cookie] {
			return out, fmt.Errorf("повтор cookie пагинации")
		}
		seen[cookie] = true
		page.SetCookie(ctl.Cookie)
	}
}

// AD returns member;range=0-1499 for large groups. Request only the next range
// on the same DC, never chase a DN to an external host.
func bhExpandMembers(ctx context.Context, c bhSearcher, e *ldap.Entry, limit int) error {
	members := []string{}
	next := 0
	ranged := false
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, "member") {
			if len(a.Values) > limit {
				a.Values = a.Values[:limit]
				return fmt.Errorf("лимит %d членов группы достигнут", limit)
			}
			return nil
		}
		if strings.HasPrefix(strings.ToLower(a.Name), "member;range=") {
			ranged = true
			start, end, terminal, err := bhRange(a.Name)
			if err != nil || start != 0 {
				return fmt.Errorf("некорректный начальный range %q", a.Name)
			}
			members = append(members, a.Values...)
			next = end + 1
			if len(members) > limit {
				e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: "member", Values: members[:limit]})
				return fmt.Errorf("лимит %d членов группы достигнут", limit)
			}
			if terminal {
				e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: "member", Values: members})
				return nil
			}
		}
	}
	if !ranged {
		return nil
	}
	var failure error
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(members) >= limit {
			failure = fmt.Errorf("лимит %d членов группы достигнут", limit)
			break
		}
		r, err := c.Search(ldap.NewSearchRequest(e.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 8, false, "(objectClass=*)", []string{fmt.Sprintf("member;range=%d-*", next)}, nil))
		if err != nil {
			failure = err
			break
		}
		if r == nil || len(r.Entries) != 1 {
			failure = fmt.Errorf("нет ответа на member range %d", next)
			break
		}
		found := false
		terminal := false
		for _, a := range r.Entries[0].Attributes {
			if !strings.HasPrefix(strings.ToLower(a.Name), "member;range=") {
				continue
			}
			start, end, done, err := bhRange(a.Name)
			if err != nil || start != next || (!done && end < start) {
				failure = fmt.Errorf("некорректный member range %q", a.Name)
				break
			}
			if len(a.Values) == 0 && !done {
				failure = fmt.Errorf("пустой незавершённый member range")
				break
			}
			found = true
			terminal = done
			members = append(members, a.Values...)
			next = end + 1
			break
		}
		if failure != nil {
			break
		}
		if !found {
			failure = fmt.Errorf("member range отсутствует в ответе")
			break
		}
		if len(members) > limit {
			members = members[:limit]
			failure = fmt.Errorf("лимит %d членов группы достигнут", limit)
			break
		}
		if terminal {
			break
		}
	}
	e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: "member", Values: members})
	return failure
}
func bhRange(name string) (start, end int, terminal bool, err error) {
	_, value, ok := strings.Cut(name, "=")
	if !ok {
		err = fmt.Errorf("range отсутствует")
		return
	}
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		err = fmt.Errorf("range отсутствует")
		return
	}
	start, err = strconv.Atoi(parts[0])
	if err != nil || start < 0 {
		err = fmt.Errorf("range start")
		return
	}
	if parts[1] == "*" {
		terminal = true
		return
	}
	end, err = strconv.Atoi(parts[1])
	if err == nil && end < start {
		err = fmt.Errorf("range end")
	}
	return
}
func bhKind(e *ldap.Entry) string {
	classes := e.GetAttributeValues("objectClass")
	for _, candidate := range []struct{ class, kind string }{{"computer", "Computer"}, {"group", "Group"}, {"domainDNS", "Domain"}, {"organizationalUnit", "OU"}, {"groupPolicyContainer", "GPO"}, {"foreignSecurityPrincipal", "Foreign"}, {"trustedDomain", "Trust"}, {"user", "User"}, {"container", "Container"}} {
		for _, class := range classes {
			if strings.EqualFold(class, candidate.class) {
				return candidate.kind
			}
		}
	}
	return ""
}
func bhGUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%08X-%04X-%04X-%X-%X", binary.LittleEndian.Uint32(b[:4]), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}
func bhSID(b []byte) string {
	s, err := accessSID(b)
	if err != nil || len(b) != 8+4*int(b[1]) || b[0] != 1 {
		return ""
	}
	return s
}
func bhScopedSID(s, domain string) string {
	if s != "" && !strings.HasPrefix(s, "S-1-5-21-") {
		return strings.ToUpper(domain) + "-" + s
	}
	return s
}
func bhID(e *ldap.Entry, kind, domain string) string {
	if kind == "User" || kind == "Computer" || kind == "Group" || kind == "Domain" || kind == "Foreign" {
		return bhScopedSID(bhSID(e.GetRawAttributeValue("objectSid")), domain)
	}
	return bhGUID(e.GetRawAttributeValue("objectGUID"))
}
func bhNumber(e *ldap.Entry, key string) int64 {
	n, _ := strconv.ParseInt(e.GetAttributeValue(key), 10, 64)
	return n
}
func bhParent(dn string) string {
	escaped := false
	for i, r := range dn {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == ',' {
			return strings.TrimSpace(dn[i+1:])
		}
	}
	return ""
}

func bhBuildGraph(entries []*ldap.Entry, g *bhGraph) {
	domain := g.summary.Domain
	refs := map[string]bhPrincipal{}
	sidRefs := map[string]bhPrincipal{}
	domainSID := ""
	for _, e := range entries {
		if bhKind(e) == "Domain" {
			domainSID = bhID(e, "Domain", domain)
		}
	}
	for _, e := range entries {
		kind := bhKind(e)
		if kind == "" || kind == "Trust" || kind == "Foreign" {
			continue
		}
		id := bhID(e, kind, domain)
		if id == "" {
			g.warn("Нет SID/GUID: " + e.DN)
			continue
		}
		ref := bhPrincipal{id, kind}
		refs[strings.ToLower(e.DN)] = ref
		sidRefs[id] = ref
	}
	for _, e := range entries {
		if bhKind(e) == "Foreign" {
			id := bhID(e, "Foreign", domain)
			if ref, ok := sidRefs[id]; ok {
				refs[strings.ToLower(e.DN)] = ref
			}
		}
	}
	seen := map[string]bool{}
	for _, e := range entries {
		kind := bhKind(e)
		ref, ok := refs[strings.ToLower(e.DN)]
		if !ok || kind == "Foreign" {
			continue
		}
		if seen[ref.ObjectIdentifier] {
			g.warn("Повтор идентификатора: " + e.DN)
			continue
		}
		seen[ref.ObjectIdentifier] = true
		name := e.GetAttributeValue("name")
		if kind == "User" || kind == "Group" {
			if v := e.GetAttributeValue("sAMAccountName"); v != "" {
				name = v
			}
		}
		if kind == "Computer" {
			if v := e.GetAttributeValue("dNSHostName"); v != "" {
				name = v
			} else {
				name = strings.TrimSuffix(e.GetAttributeValue("sAMAccountName"), "$") + "." + domain
			}
		}
		if kind == "GPO" && e.GetAttributeValue("displayName") != "" {
			name = e.GetAttributeValue("displayName")
		}
		if kind == "Domain" {
			name = domain
		} else if kind != "Computer" {
			name += "@" + domain
		}
		props := map[string]any{"name": strings.ToUpper(name), "domain": domain, "domainsid": domainSID, "distinguishedname": strings.ToUpper(e.DN)}
		if v := e.GetAttributeValue("description"); v != "" {
			props["description"] = v
		}
		if v := e.GetAttributeValue("whenCreated"); v != "" {
			if t, err := time.Parse("20060102150405.0Z", v); err == nil {
				props["whencreated"] = t.Unix()
			}
		}
		node := bhNode{"ObjectIdentifier": ref.ObjectIdentifier, "Properties": props, "IsDeleted": false}
		// Omit IsACLProtected and Aces: no security descriptor was collected.
		if parent, ok := refs[strings.ToLower(bhParent(e.DN))]; ok && (parent.ObjectType == "Domain" || parent.ObjectType == "OU" || parent.ObjectType == "Container") {
			node["ContainedBy"] = parent
			g.summary.Relationships++
		}
		switch kind {
		case "User", "Computer":
			if e.GetAttributeValue("userAccountControl") != "" {
				uac := bhNumber(e, "userAccountControl")
				props["enabled"] = uac&2 == 0
				props["unconstraineddelegation"] = uac&0x80000 != 0
				props["trustedtoauth"] = uac&0x1000000 != 0
				props["sensitive"] = uac&0x100000 != 0
				props["dontreqpreauth"] = uac&0x400000 != 0
				props["passwordnotreqd"] = uac&0x20 != 0
				props["pwdneverexpires"] = uac&0x10000 != 0
			}
			if e.GetAttributeValue("adminCount") != "" {
				props["admincount"] = bhNumber(e, "adminCount") == 1
			}
			spns := e.GetAttributeValues("servicePrincipalName")
			if spns == nil {
				spns = []string{}
			}
			props["serviceprincipalnames"] = spns
			props["hasspn"] = len(spns) > 0
			for _, key := range []string{"pwdLastSet", "lastLogon", "lastLogonTimestamp"} {
				if e.GetAttributeValue(key) != "" {
					n := bhNumber(e, key)
					if n > 0 {
						n = n/10000000 - 11644473600
					}
					props[strings.ToLower(key)] = n
				}
			}
			rawSID := bhSID(e.GetRawAttributeValue("objectSid"))
			if rid := e.GetAttributeValue("primaryGroupID"); rid != "" {
				if n, err := strconv.ParseUint(rid, 10, 32); err == nil {
					if i := strings.LastIndex(rawSID, "-"); i > 0 {
						node["PrimaryGroupSID"] = rawSID[:i] + "-" + strconv.FormatUint(n, 10)
						g.summary.Relationships++
					}
				}
			}
			if kind == "Computer" {
				props["operatingsystem"] = strings.TrimSpace(e.GetAttributeValue("operatingSystem") + " " + e.GetAttributeValue("operatingSystemVersion"))
				node["IsDC"] = bhNumber(e, "userAccountControl")&0x2000 != 0
				for _, field := range []string{"Sessions", "PrivilegedSessions", "RegistrySessions"} {
					node[field] = map[string]any{"Collected": false, "FailureReason": "Not collected: directory-only profile", "Results": []any{}}
				}
			}
		case "Group":
			members := []bhPrincipal{}
			unique := map[string]bool{}
			for _, dn := range e.GetAttributeValues("member") {
				if member, ok := refs[strings.ToLower(dn)]; ok {
					if !unique[member.ObjectIdentifier] {
						unique[member.ObjectIdentifier] = true
						members = append(members, member)
						g.summary.Relationships++
					}
				} else {
					g.warn("Не разрешён член группы " + e.DN + ": " + dn)
				}
			}
			node["Members"] = members
			if e.GetAttributeValue("adminCount") != "" {
				props["admincount"] = bhNumber(e, "adminCount") == 1
			}
		case "OU":
			props["blocksinheritance"] = bhNumber(e, "gPOptions")&1 != 0
		case "GPO":
			props["gpcpath"] = e.GetAttributeValue("gPCFileSysPath")
		case "Domain":
			props["collected"] = true
		}
		if kind == "Domain" || kind == "OU" {
			node["Links"] = bhLinks(e, refs, g)
			if kind == "Domain" {
				node["Trusts"] = bhTrusts(entries, g)
			}
		}
		plural := map[string]string{"User": "users", "Computer": "computers", "Group": "groups", "Domain": "domains", "OU": "ous", "GPO": "gpos", "Container": "containers"}[kind]
		g.nodes[plural] = append(g.nodes[plural], node)
	}
	for _, typ := range bloodHoundTypes {
		sort.Slice(g.nodes[typ], func(i, j int) bool {
			return g.nodes[typ][i]["ObjectIdentifier"].(string) < g.nodes[typ][j]["ObjectIdentifier"].(string)
		})
	}
}
func bhLinks(e *ldap.Entry, refs map[string]bhPrincipal, g *bhGraph) []map[string]any {
	links := []map[string]any{}
	for _, part := range strings.Split(e.GetAttributeValue("gPLink"), "]") {
		if part == "" {
			continue
		}
		_, value, ok := strings.Cut(part, "LDAP://")
		if !ok {
			_, value, ok = strings.Cut(part, "ldap://")
		}
		dn, flags, split := strings.Cut(value, ";")
		if !ok || !split {
			g.warn("Некорректный gPLink: " + e.DN)
			continue
		}
		n, err := strconv.Atoi(flags)
		if err != nil {
			g.warn("Некорректные флаги gPLink: " + e.DN)
			continue
		}
		if n&1 != 0 {
			continue
		}
		ref, found := refs[strings.ToLower(dn)]
		if !found || ref.ObjectType != "GPO" {
			g.warn("Не разрешена ссылка GPO: " + dn)
			continue
		}
		id := ref.ObjectIdentifier
		links = append(links, map[string]any{"GUID": id, "IsEnforced": n&2 != 0})
		g.summary.Relationships++
	}
	return links
}
func bhTrusts(entries []*ldap.Entry, g *bhGraph) []map[string]any {
	out := []map[string]any{}
	for _, e := range entries {
		if bhKind(e) != "Trust" {
			continue
		}
		valid := true
		for _, key := range []string{"trustDirection", "trustType", "trustAttributes"} {
			if _, err := strconv.ParseUint(e.GetAttributeValue(key), 10, 32); err != nil {
				valid = false
			}
		}
		if !valid {
			g.warn("Недоступны числовые атрибуты доверия: " + e.DN)
			continue
		}
		sid := bhSID(e.GetRawAttributeValue("securityIdentifier"))
		partner := e.GetAttributeValue("trustPartner")
		direction := map[int64]string{0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}[bhNumber(e, "trustDirection")]
		if sid == "" || partner == "" || direction == "" {
			g.warn("Неполные атрибуты доверия: " + e.DN)
			continue
		}
		attrs := bhNumber(e, "trustAttributes")
		kind := "External"
		filter := true
		transitive := false
		switch {
		case attrs&32 != 0:
			kind = "ParentChild"
			filter = attrs&4 != 0
			transitive = true
		case attrs&8 != 0:
			kind = "Forest"
			filter = attrs&64 == 0
			transitive = true
		case bhNumber(e, "trustType") == 3:
			kind = "Realm"
			transitive = attrs&1 == 0
		}
		tgt := attrs&0x800 != 0 || (attrs&32 != 0 && attrs&0x200 == 0)
		out = append(out, map[string]any{"TargetDomainSid": sid, "TargetDomainName": strings.ToUpper(partner), "TrustDirection": direction, "TrustType": kind, "TrustAttributes": attrs, "IsTransitive": transitive, "SidFilteringEnabled": filter, "TGTDelegationEnabled": tgt})
		g.summary.Relationships++
	}
	return out
}

func writeBloodHound(ctx context.Context, dir string, g bhGraph) (path string, err error) {
	if err = os.MkdirAll(dir, 0700); err != nil {
		return
	}
	file, err := os.CreateTemp(dir, "bloodhound-ce-*.zip")
	if err != nil {
		return "", err
	}
	path = file.Name()
	success := false
	defer func() {
		if !success {
			_ = file.Close()
			_ = os.Remove(path)
			_ = os.Remove(path + ".summary.json")
		}
	}()
	if err = file.Chmod(0600); err != nil {
		return
	}
	writer := zip.NewWriter(file)
	for _, typ := range bloodHoundTypes {
		if err = ctx.Err(); err != nil {
			_ = writer.Close()
			return
		}
		var member interface{ Write([]byte) (int, error) }
		member, err = writer.Create(typ + ".json")
		if err != nil {
			_ = writer.Close()
			return
		}
		envelope := map[string]any{"data": g.nodes[typ], "meta": map[string]any{"type": typ, "count": len(g.nodes[typ]), "version": 6, "methods": bloodHoundMethods}}
		if err = json.NewEncoder(member).Encode(envelope); err != nil {
			_ = writer.Close()
			return
		}
	}
	if err = writer.Close(); err != nil {
		return
	}
	if err = file.Close(); err != nil {
		return
	}
	if err = ctx.Err(); err != nil {
		return
	}
	var data []byte
	data, err = json.MarshalIndent(g.summary, "", "  ")
	if err != nil {
		return
	}
	err = os.WriteFile(path+".summary.json", append(data, '\n'), 0600)
	if err != nil {
		return
	}
	// The companion summary is deliberately outside the ingest ZIP.
	path = filepath.Clean(path)
	success = true
	return
}
