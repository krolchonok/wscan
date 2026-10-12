package adscan

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

type bhSearchFunc func(*ldap.SearchRequest) (*ldap.SearchResult, error)

func (f bhSearchFunc) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) { return f(r) }
func testBHSID(rid ...uint32) string {
	b := make([]byte, 8+4*len(rid))
	b[0] = 1
	b[1] = byte(len(rid))
	b[7] = 5
	for i, v := range rid {
		binary.LittleEndian.PutUint32(b[8+i*4:], v)
	}
	return string(b)
}
func testBHEntry(dn, class string, attrs map[string][]string) *ldap.Entry {
	attrs["objectClass"] = []string{"top", class}
	return ldap.NewEntry(dn, attrs)
}
func testBHDirectory() []*ldap.Entry {
	base := "DC=lab,DC=example"
	guid := string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	return []*ldap.Entry{
		testBHEntry(base, "domainDNS", map[string][]string{"name": {"lab"}, "objectSid": {testBHSID(21, 1, 2, 3)}, "gPLink": {"[LDAP://CN={POLICY-NAME},CN=Policies,CN=System," + base + ";2]"}}),
		testBHEntry("CN=Users,"+base, "container", map[string][]string{"name": {"Users"}, "objectGUID": {guid}}),
		testBHEntry("CN=alice,CN=Users,"+base, "user", map[string][]string{"name": {"alice"}, "sAMAccountName": {"alice"}, "objectSid": {testBHSID(21, 1, 2, 3, 1100)}, "primaryGroupID": {"513"}, "userAccountControl": {"512"}, "pwdLastSet": {"133000000000000000"}}),
		testBHEntry("CN=Domain Users,CN=Users,"+base, "group", map[string][]string{"name": {"Domain Users"}, "objectSid": {testBHSID(21, 1, 2, 3, 513)}, "member": {"CN=alice,CN=Users," + base}}),
		testBHEntry("CN={POLICY-NAME},CN=Policies,CN=System,"+base, "groupPolicyContainer", map[string][]string{"name": {"{POLICY-NAME}"}, "displayName": {"Test policy"}, "objectGUID": {string([]byte{2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})}}),
	}
}
func TestBloodHoundDomainCollectionAndZIP(t *testing.T) {
	entries := testBHDirectory()
	requests := 0
	search := bhSearchFunc(func(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
		requests++
		if requests == 1 {
			if r.BaseDN != "" || r.Scope != ldap.ScopeBaseObject {
				t.Fatalf("RootDSE request %+v", r)
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("", map[string][]string{"defaultNamingContext": {"DC=lab,DC=example"}})}}, nil
		}
		if requests == 2 {
			if r.BaseDN != "DC=lab,DC=example" || r.Scope != ldap.ScopeBaseObject {
				t.Fatal(r)
			}
			return &ldap.SearchResult{Entries: entries[:1]}, nil
		}
		if r.BaseDN != "DC=lab,DC=example" || r.Scope != ldap.ScopeWholeSubtree {
			t.Fatalf("scope escaped: %+v", r)
		}
		for _, a := range r.Attributes {
			if strings.Contains(strings.ToLower(a), "password") || a == "nTSecurityDescriptor" {
				t.Fatalf("unexpected attribute %s", a)
			}
		}
		return &ldap.SearchResult{Entries: entries}, nil
	})
	g, err := collectBloodHound(context.Background(), search, BloodHoundOptions{AccessOptions: AccessOptions{Host: "dc.lab.example", Domain: "lab.example", MaxObjects: 100}}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if g.summary.Partial || g.total() != 5 || requests != 3 {
		t.Fatalf("summary %+v", g.summary)
	}
	user := g.nodes["users"][0]
	if user["PrimaryGroupSID"] != "S-1-5-21-1-2-3-513" {
		t.Fatal(user)
	}
	if user["ContainedBy"].(bhPrincipal).ObjectType != "Container" {
		t.Fatal(user)
	}
	group := g.nodes["groups"][0]
	if len(group["Members"].([]bhPrincipal)) != 1 {
		t.Fatal(group)
	}
	links := g.nodes["domains"][0]["Links"].([]map[string]any)
	if len(links) != 1 || links[0]["GUID"] != g.nodes["gpos"][0]["ObjectIdentifier"] || links[0]["GUID"] == "POLICY-NAME" {
		t.Fatal(links)
	}
	path, err := writeBloodHound(context.Background(), t.TempDir(), g)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if len(z.File) != 7 {
		t.Fatalf("ZIP members %d", len(z.File))
	}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Data []map[string]any `json:"data"`
			Meta struct {
				Type                    string `json:"type"`
				Version, Count, Methods int
			}
		}
		err = json.NewDecoder(r).Decode(&envelope)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if envelope.Data == nil || envelope.Meta.Version != 6 || envelope.Meta.Count != len(envelope.Data) || envelope.Meta.Methods != 673 || f.Name != envelope.Meta.Type+".json" {
			t.Fatalf("invalid envelope %+v", envelope)
		}
	}
	data, err := os.ReadFile(path + ".summary.json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "not_collected") {
		t.Fatal(string(data))
	}
}
func TestBloodHoundLargeGroupRanges(t *testing.T) {
	e := testBHEntry("CN=group,DC=lab,DC=example", "group", map[string][]string{"member;range=0-1": {"CN=a", "CN=b"}})
	called := 0
	c := bhSearchFunc(func(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
		called++
		if r.BaseDN != e.DN || r.Scope != ldap.ScopeBaseObject || r.Attributes[0] != "member;range=2-*" {
			t.Fatal(r)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(e.DN, map[string][]string{"member;range=2-*": {"CN=c"}})}}, nil
	})
	if err := bhExpandMembers(context.Background(), c, e, 10); err != nil {
		t.Fatal(err)
	}
	if called != 1 || len(e.GetAttributeValues("member")) != 3 {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name  string
		limit int
		reply string
	}{{"limit", 2, "member;range=2-*"}, {"repeated", 10, "member;range=0-1"}, {"missing", 10, "description"}} {
		t.Run(tc.name, func(t *testing.T) {
			e := ldap.NewEntry("CN=group", map[string][]string{"member;range=0-1": {"CN=a", "CN=b"}})
			c := bhSearchFunc(func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(e.DN, map[string][]string{tc.reply: {"CN=c"}})}}, nil
			})
			if err := bhExpandMembers(context.Background(), c, e, tc.limit); err == nil {
				t.Fatal("expected incomplete group")
			}
			if len(e.GetAttributeValues("member")) != 2 {
				t.Fatal(e)
			}
		})
	}
}
func TestBloodHoundPagingPartialAndCancellation(t *testing.T) {
	ctx := context.Background()
	page := 0
	c := bhSearchFunc(func(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
		page++
		ctl := ldap.NewControlPaging(2)
		ctl.SetCookie([]byte("same"))
		return &ldap.SearchResult{Entries: testBHDirectory()[:1], Controls: []ldap.Control{ctl}}, nil
	})
	entries, err := bhPagedSearch(ctx, c, "DC=lab,DC=example", bhAttributes, 3)
	if err == nil || len(entries) != 2 || page != 2 {
		t.Fatalf("entries=%d pages=%d err=%v", len(entries), page, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := bhPagedSearch(cancelled, c, "base", nil, 5); err != context.Canceled {
		t.Fatal(err)
	}
	dir := t.TempDir()
	g := bhGraph{nodes: map[string][]bhNode{}}
	if _, err := writeBloodHound(cancelled, dir, g); err != context.Canceled {
		t.Fatal(err)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 {
		t.Fatal(files)
	}
}
func TestBloodHoundUnknownMemberIsPartial(t *testing.T) {
	entries := testBHDirectory()
	entries[3].Attributes = append(entries[3].Attributes, &ldap.EntryAttribute{Name: "member", Values: []string{"CN=unknown"}})
	// Replace the original member attribute rather than relying on duplicate values.
	entries[3] = testBHEntry(entries[3].DN, "group", map[string][]string{"objectSid": {testBHSID(21, 1, 2, 3, 513)}, "member": {"CN=unknown"}})
	g := bhGraph{nodes: map[string][]bhNode{}, summary: BloodHoundSummary{Domain: "LAB.EXAMPLE"}}
	bhBuildGraph(entries, &g)
	if !g.summary.Partial || len(g.nodes["groups"][0]["Members"].([]bhPrincipal)) != 0 {
		t.Fatal(g.summary)
	}
}
func TestBloodHoundRejectsAnonymousAndBadIDs(t *testing.T) {
	_, err := RunBloodHound(context.Background(), BloodHoundOptions{AccessOptions: AccessOptions{Host: "dc.lab.example", Domain: "lab.example", ExportDir: t.TempDir()}})
	if err == nil || !strings.Contains(err.Error(), "учётку") {
		t.Fatal(err)
	}
	if got := bhGUID([]byte{1}); got != "" {
		t.Fatal(got)
	}
	for _, b := range [][]byte{nil, {}, make([]byte, 8), []byte(testBHSID(21, 1, 2, 3) + "x")} {
		if got := bhSID(b); got != "" {
			t.Fatal(got)
		}
	}
	if got := bhScopedSID("S-1-5-32-544", "lab.example"); got != "LAB.EXAMPLE-S-1-5-32-544" {
		t.Fatal(got)
	}
}
