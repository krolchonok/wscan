package versionaudit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"wscan/internal/domain"
)

func testDB(t *testing.T) *Database {
	t.Helper()
	doc := map[string]any{"schema_version": 1, "products": map[string]any{
		"gitlab/gitlab":     map[string]any{"vendor": "gitlab", "product": "gitlab", "aliases": []string{"GitLab", "gitlab-ee", "gitlab-ce"}},
		"mikrotik/routeros": map[string]any{"vendor": "mikrotik", "product": "routeros", "aliases": []string{"Router OS", "RouterOS"}},
	}, "checks": map[string]any{}}
	checks := doc["checks"].(map[string]any)
	for i, key := range []string{"gitlab/gitlab", "mikrotik/routeros"} {
		groups := [][]string{{">=16.0.0", "<16.0.3"}, {">=16.1.0", "<16.1.2"}}
		if i == 1 {
			groups = [][]string{{">=6.0", "<6.49.13"}, {">=7.0", "<7.14"}}
		}
		ch := map[string]any{"name": "test CVE", "source_id": "CVE-2024-12345-version", "severity": "high", "bindings": []any{map[string]any{"product": key, "confidence": "curated"}}, "evidence": map[string]any{"kind": "version", "confidence": "curated"}, "version_constraints": map[string]any{"any_of": groups, "all_of_within_group": true, "comparison": "numeric_release_components", "prerelease": "excluded"}}
		checks[key] = ch
		checks[key+"duplicate"] = ch
	}
	b, _ := json.Marshal(doc)
	path := filepath.Join(t.TempDir(), "products.json")
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	db, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	return db
}
func TestOfflineComparison(t *testing.T) {
	db := testDB(t)
	cases := []struct {
		product, version string
		hit              bool
		reason           string
	}{
		{"GitLab", "16.0.0", true, ""}, {"GitLab", "16.0.2-ee", true, ""}, {"GitLab", "16.0.3", false, "совпадений"},
		{"GitLab", "16.1.1", true, ""}, {"GitLab", "16.1.2", false, "совпадений"}, {"GitLab", "15.9.9", false, "совпадений"},
		{"GitLab", "16.0", false, "неполная"}, {"GitLab", "16.0.1-rc1", false, "стабильным"}, {"GitLab", "", false, "не сохранена"},
		{"RouterOS", "6.49.12", true, ""}, {"MikroTik RouterOS", "7.13.5", true, ""}, {"Router OS", "7.14", false, "совпадений"},
		{"RouterOS", "7.13-ee", false, "суффикс"}, {"RouterOS", "999999999999999999999999.0", false, "некорректная"},
		{"nginx", "16.0.1", false, "нет локальных"}, {"GitLab proxy", "16.0.1", false, "нет локальных"}, {"", "16.0.1", false, "продукт не определён"},
	}
	for _, tc := range cases {
		t.Run(tc.product+tc.version, func(t *testing.T) {
			fs, e := db.Assess(context.Background(), domain.Service{Host: "invalid.invalid", Port: 80, Protocol: "tcp", Name: "gitlab", Product: tc.product, Version: tc.version})
			if e != nil {
				t.Fatal(e)
			}
			if len(fs) != 1 {
				t.Fatalf("duplicate findings: %d", len(fs))
			}
			if (fs[0].Severity == "high") != tc.hit {
				t.Fatalf("unexpected finding: %+v", fs[0])
			}
			if !strings.Contains(fs[0].Name, tc.reason) {
				t.Fatal(fs[0].Name)
			}
			if fs[0].Protocol != "offline" || fs[0].Request != "" || fs[0].Response != "" {
				t.Fatal("network evidence must be absent")
			}
		})
	}
}
func TestCPEOwnVersionAndConflict(t *testing.T) {
	db := testDB(t)
	s := domain.Service{Host: "invalid.invalid", Port: 22, Protocol: "tcp", Product: "OpenSSH", Version: "9.9", CPE: []string{"cpe:/o:mikrotik:routeros:7.13.5"}}
	fs, e := db.Assess(context.Background(), s)
	if e != nil || len(fs) != 1 || fs[0].Severity != "high" || !strings.Contains(fs[0].Evidence, "7.13.5") {
		t.Fatalf("%+v %v", fs, e)
	}
	s.CPE = []string{"cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*"}
	fs, _ = db.Assess(context.Background(), s)
	if !strings.Contains(fs[0].Name, "не сохранена") {
		t.Fatal("application version assigned to OS", fs)
	}
	s.Product = "RouterOS"
	s.Version = "7.13.5"
	s.CPE = []string{"cpe:/o:mikrotik:routeros:7.14"}
	fs, _ = db.Assess(context.Background(), s)
	if !strings.Contains(fs[0].Name, "противоречат") {
		t.Fatal(fs)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = db.Assess(ctx, s); e == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestRejectUnsupportedRangesAndMissingDatabase(t *testing.T) {
	for _, c := range []*constraints{{AnyOf: [][]string{{"<7.14"}}, All: false, Comparison: "numeric_release_components", Prerelease: "excluded"}, {AnyOf: [][]string{{"invalid"}}, All: true, Comparison: "numeric_release_components", Prerelease: "excluded"}, {AnyOf: [][]string{{}}, All: true, Comparison: "numeric_release_components", Prerelease: "excluded"}} {
		if _, e := compile(c); e == nil {
			t.Fatal("invalid range accepted")
		}
	}
	if _, e := Load(filepath.Join(t.TempDir(), "absent.json")); e == nil || !strings.Contains(e.Error(), "автоматической загрузки нет") {
		t.Fatal(e)
	}
}
func TestReviewedLocalLibrary(t *testing.T) {
	path := filepath.Join("..", "..", "library", "products.json")
	if _, e := os.Stat(path); os.IsNotExist(e) {
		t.Skip("local library not installed")
	}
	db, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if db.Rules == 0 {
		t.Fatal("no rules loaded")
	}
	fs, e := db.Assess(context.Background(), domain.Service{Host: "invalid.invalid", Port: 80, Protocol: "tcp", Product: "MikroTik RouterOS", Version: "7.13.5"})
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, f := range fs {
		if strings.Contains(f.TemplateID, "CVE-2023-47310") {
			found = true
		}
	}
	if !found {
		t.Fatal("curated range not matched")
	}
}
