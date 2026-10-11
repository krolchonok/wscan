// Package versionaudit correlates saved fingerprints with local CVE ranges.
// It performs no network operations and does not execute templates.
package versionaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"wscan/internal/domain"
)

type product struct {
	Vendor  string
	Product string
	Aliases []string
	CPEs    []string `json:"cpes"`
}
type constraints struct {
	AnyOf      [][]string `json:"any_of"`
	All        bool       `json:"all_of_within_group"`
	Comparison string
	Prerelease string
}
type check struct {
	Name       string
	Severity   string
	SourceID   string `json:"source_id"`
	References []string
	Bindings   []struct {
		Product    string
		Confidence string
	}
	Evidence struct {
		Kind       string
		Confidence string
	}
	Ranges       *constraints    `json:"version_constraints"`
	Affected     json.RawMessage `json:"affected_service"`
	Requirements json.RawMessage `json:"vulnerability_requirements"`
}
type rule struct {
	check
	CVE    string
	bounds [][]bound
}
type bound struct {
	op      string
	version []uint64
}
type Database struct {
	products map[string]product
	aliases  map[string]string
	rules    map[string][]rule
	Digest   string
	Rules    int
	Ignored  int
}

var versionRE = regexp.MustCompile(`^v?([0-9]+(?:\.[0-9]+)+)(?:-(?:ee|ce))?$`)
var constraintRE = regexp.MustCompile(`^(>=|<=|>|<|=)([0-9]+(?:\.[0-9]+)*)$`)
var cveRE = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,}`)

func normalize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, s)
}
func parse(s string) ([]uint64, error) {
	parts := strings.Split(s, ".")
	out := make([]uint64, len(parts))
	for i, p := range parts {
		v, e := strconv.ParseUint(p, 10, 64)
		if e != nil {
			return nil, e
		}
		out[i] = v
	}
	return out, nil
}
func compare(a, b []uint64) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y uint64
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}
func compile(c *constraints) ([][]bound, error) {
	if c.Comparison != "numeric_release_components" || !c.All || c.Prerelease != "excluded" || len(c.AnyOf) == 0 {
		return nil, fmt.Errorf("unsupported range semantics")
	}
	var groups [][]bound
	for _, g := range c.AnyOf {
		if len(g) == 0 {
			return nil, fmt.Errorf("empty range")
		}
		var bs []bound
		for _, expr := range g {
			m := constraintRE.FindStringSubmatch(expr)
			if m == nil {
				return nil, fmt.Errorf("invalid constraint")
			}
			v, e := parse(m[2])
			if e != nil {
				return nil, e
			}
			bs = append(bs, bound{m[1], v})
		}
		groups = append(groups, bs)
	}
	return groups, nil
}
func (r rule) matches(v []uint64) bool {
	for _, g := range r.bounds {
		ok := true
		for _, b := range g {
			c := compare(v, b.version)
			switch b.op {
			case ">=":
				ok = ok && c >= 0
			case "<=":
				ok = ok && c <= 0
			case ">":
				ok = ok && c > 0
			case "<":
				ok = ok && c < 0
			case "=":
				ok = ok && c == 0
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func Load(path string) (*Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("локальная база CVE: %w (автоматической загрузки нет)", err)
	}
	var doc struct {
		Schema   int `json:"schema_version"`
		Products map[string]product
		Checks   map[string]check
	}
	if err = json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Schema != 1 || len(doc.Products) == 0 || doc.Checks == nil {
		return nil, fmt.Errorf("неподдерживаемая структура products.json")
	}
	sum := sha256.Sum256(data)
	db := &Database{products: doc.Products, aliases: map[string]string{}, rules: map[string][]rule{}, Digest: hex.EncodeToString(sum[:])}
	for _, ch := range doc.Checks {
		if ch.Ranges == nil {
			continue
		}
		bounds, e := compile(ch.Ranges)
		cve := cveRE.FindString(ch.SourceID)
		if e != nil || cve == "" || ch.Evidence.Kind != "version" || ch.Evidence.Confidence != "curated" {
			db.Ignored++
			continue
		}
		seen := map[string]bool{}
		for _, b := range ch.Bindings {
			if _, ok := doc.Products[b.Product]; !ok || b.Confidence != "curated" || seen[b.Product] {
				continue
			}
			seen[b.Product] = true
			db.rules[b.Product] = append(db.rules[b.Product], rule{ch, cve, bounds})
			db.Rules++
		}
	}
	for key, rs := range db.rules {
		sort.Slice(rs, func(i, j int) bool { return rs[i].CVE < rs[j].CVE })
		db.rules[key] = rs
	}
	// Whole-label matching only; ambiguous aliases remain unresolved.
	for key, p := range db.products {
		labels := append([]string{key, p.Product, p.Vendor + " " + p.Product}, p.Aliases...)
		for _, label := range labels {
			n := normalize(label)
			if n == "" {
				continue
			}
			old, exists := db.aliases[n]
			if exists && old != key {
				db.aliases[n] = ""
			} else if !exists {
				db.aliases[n] = key
			}
		}
	}
	return db, nil
}

type component struct {
	key, version string
	conflict     bool
}

func cpeParts(s string) (string, string, string) {
	parts := strings.Split(s, ":")
	if strings.HasPrefix(s, "cpe:/") && len(parts) >= 4 {
		v := ""
		if len(parts) >= 5 {
			v = parts[4]
		}
		return parts[2], parts[3], v
	}
	if strings.HasPrefix(s, "cpe:2.3:") && len(parts) >= 6 {
		return parts[3], parts[4], parts[5]
	}
	return "", "", ""
}
func (db *Database) components(s domain.Service) []component {
	mapped := db.aliases[normalize(s.Product)]
	cs := map[string]component{}
	if mapped != "" {
		cs[mapped] = component{key: mapped, version: s.Version}
	}
	for _, cpe := range s.CPE {
		vendor, name, v := cpeParts(cpe)
		if vendor == "" {
			continue
		}
		for key, p := range db.products {
			if vendor != p.Vendor || name != p.Product {
				continue
			}
			if v == "*" || v == "-" {
				v = ""
			}
			old, exists := cs[key]
			if !exists {
				cs[key] = component{key: key, version: v}
				continue
			}
			if v == "" {
				continue
			}
			if old.version != "" && old.version != v {
				old.conflict = true
			}
			if old.version == "" {
				old.version = v
			}
			cs[key] = old
		}
	}
	keys := make([]string, 0, len(cs))
	for k := range cs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []component
	for _, k := range keys {
		out = append(out, cs[k])
	}
	return out
}

// Assess always reports coverage, including missing or unusable fingerprints.
func (db *Database) Assess(ctx context.Context, s domain.Service) ([]domain.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cs := db.components(s)
	if len(cs) == 0 {
		reason := "нет локальных диапазонов для сохранённого продукта"
		if strings.TrimSpace(s.Product) == "" {
			reason = "продукт не определён; по порту и имени протокола продукт не угадывается"
		}
		return []domain.Finding{db.info(s, "", s.Version, reason)}, nil
	}
	var out []domain.Finding
	for _, c := range cs {
		rs := db.rules[c.key]
		reason := ""
		switch {
		case c.conflict:
			reason = "сохранённые версии продукта и CPE противоречат друг другу"
		case c.version == "":
			reason = "версия не сохранена"
		case len(rs) == 0:
			reason = "нет локальных диапазонов CVE для продукта"
		}
		m := versionRE.FindStringSubmatch(strings.ToLower(strings.TrimSpace(c.version)))
		var v []uint64
		if reason == "" {
			if m == nil {
				reason = "версия не является стабильным числовым релизом; beta/rc и vendor suffix не оцениваются"
			} else {
				var err error
				v, err = parse(m[1])
				if err != nil || c.key == "gitlab/gitlab" && len(v) < 3 {
					reason = "неполная или некорректная версия"
				}
				if c.key != "gitlab/gitlab" && strings.Contains(m[0], "-") {
					reason = "суффикс редакции поддерживается только для GitLab"
				}
			}
		}
		if reason != "" {
			out = append(out, db.info(s, c.key, c.version, reason))
			continue
		}
		seen := map[string]bool{}
		hits := 0
		for _, r := range rs {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !r.matches(v) || seen[r.CVE] {
				continue
			}
			seen[r.CVE] = true
			hits++
			f := db.base(s, c.key, c.version)
			f.TemplateID = "offline/cve/" + r.CVE + "/" + c.key
			f.Name = r.CVE + " — " + c.key + " " + c.version + ": потенциально по версии"
			f.Severity = r.Severity
			f.Risk = "version-correlation"
			f.References = append([]string(nil), r.References...)
			f.Description = "Совпадение сохранённой версии с локальным диапазоном CVE. Доступность затронутого компонента, условия эксплуатации и наличие исправлений/backport не проверены. Сетевых запросов нет.\n" + r.Name
			evidence := map[string]any{"product": c.key, "observed_version": c.version, "ranges": r.Ranges.AnyOf, "affected_service": r.Affected, "vulnerability_requirements": r.Requirements, "database_sha256": db.Digest, "source": "local products.json", "comparison": "numeric_release_components"}
			b, _ := json.MarshalIndent(evidence, "", "  ")
			f.Evidence = string(b)
			out = append(out, f)
		}
		if hits == 0 {
			out = append(out, db.info(s, c.key, c.version, fmt.Sprintf("совпадений среди %d локальных правил нет; это не подтверждает отсутствие CVE", len(rs))))
		}
	}
	return out, nil
}
func (db *Database) base(s domain.Service, key, v string) domain.Finding {
	target := s.Target
	if target == "" {
		target = s.Host
	}
	return domain.Finding{Target: target, MatchedAt: "offline://" + net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) + "/" + s.Protocol, Protocol: "offline", MatcherName: "version-correlation", Time: time.Now().UTC()}
}
func (db *Database) info(s domain.Service, key, v, reason string) domain.Finding {
	f := db.base(s, key, v)
	f.TemplateID = "offline/cve/coverage/" + key
	label := key
	if label == "" {
		label = strings.TrimSpace(s.Product)
	}
	if label == "" {
		label = "неизвестный продукт"
	}
	if v != "" {
		label += " " + v
	}
	f.Name = "CVE: " + label + " — " + reason
	f.Severity = "info"
	f.Description = "Офлайн-сверка сохранённых версий, без сканирования и сетевых запросов. " + reason
	b, _ := json.MarshalIndent(map[string]any{"product": s.Product, "canonical_product": key, "version": v, "status": reason, "database_sha256": db.Digest, "rules_loaded": db.Rules, "ignored_ranges": db.Ignored}, "", "  ")
	f.Evidence = string(b)
	return f
}
