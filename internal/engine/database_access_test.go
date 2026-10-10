package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wscan/internal/domain"
	tpl "wscan/internal/template"
)

func databaseAuditTemplate(t *testing.T, source string) domain.Template {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../../library/nuclei-templates", source))
	if err != nil {
		t.Fatal(err)
	}
	template, err := tpl.ForExecution(raw, source)
	if err != nil || !template.Compatible {
		t.Fatalf("template parse=%v unsupported=%v", err, template.Unsupported)
	}
	return template
}
func TestElasticsearchRESTCredentialsDoNotMatchAnonymous(t *testing.T) {
	template := databaseAuditTemplate(t, "custom/database-audit/elasticsearch-rest-default-login.yaml")
	for _, tc := range []struct {
		name, password   string
		anonymous, match bool
	}{
		{"anonymous", "", true, false}, {"default", "changeme", false, true}, {"empty", "", false, true}, {"protected", "strong-password", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/_security/_authenticate" {
					t.Errorf("unexpected request %s", r.URL.Path)
				}
				u, p, ok := r.BasicAuth()
				if !tc.anonymous && (!ok || u != "elastic" || p != tc.password) {
					w.WriteHeader(401)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"username":"elastic","roles":["superuser"]}`))
			}))
			defer srv.Close()
			result, err := New(&fakeStore{}, Config{Concurrency: 1, TimeoutSeconds: 2}).Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{template})
			if err != nil || len(result.Errors) > 0 || (len(result.Findings) > 0) != tc.match {
				t.Fatalf("findings=%d errors=%v err=%v", len(result.Findings), result.Errors, err)
			}
		})
	}
}
func TestCouchDBEmptyPasswordAndIdentity(t *testing.T) {
	template := databaseAuditTemplate(t, "http/default-logins/couchdb/couchdb-default-login.yaml")
	for _, identity := range []string{"admin", "guest"} {
		t.Run(identity, func(t *testing.T) {
			sawEmpty := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.ParseForm()
				if r.Form.Get("name") != "admin" || r.Form.Get("password") != "" {
					w.WriteHeader(401)
					return
				}
				sawEmpty = true
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Set-Cookie", "AuthSession=fixture; HttpOnly")
				w.Write([]byte(`{"ok":true,"name":"` + identity + `","roles":["_admin"]}`))
			}))
			defer srv.Close()
			result, err := New(&fakeStore{}, Config{Concurrency: 1, TimeoutSeconds: 2}).Scan(context.Background(), domain.Project{ID: 1, Targets: []string{srv.URL}}, []domain.Template{template})
			if err != nil || len(result.Errors) > 0 || !sawEmpty || (len(result.Findings) > 0) != (identity == "admin") {
				t.Fatalf("sawEmpty=%v findings=%d errors=%v err=%v", sawEmpty, len(result.Findings), result.Errors, err)
			}
		})
	}
}
func TestMySQLTemplatePreservesEmptyValues(t *testing.T) {
	template := databaseAuditTemplate(t, "javascript/misconfiguration/mysql/mysql-empty-password.yaml")
	if len(template.JavaScript) != 1 {
		t.Fatal("missing JS request")
	}
	r := template.JavaScript[0]
	combos, errs := jsPayloadCombos(r, nil, map[string]string{"Host": "127.0.0.1", "Port": "3306"}, "", "javascript/misconfiguration/mysql/mysql-empty-password.yaml")
	if len(errs) > 0 || len(combos) != 2 {
		t.Fatalf("combos=%v errors=%v", combos, errs)
	}
	foundEmpty := false
	for _, c := range combos {
		if c["username"] == "" {
			foundEmpty = true
		}
	}
	if !foundEmpty || strings.TrimSpace(r.Args["Pass"].(string)) != "" || r.Args["Pass"] != "" {
		t.Fatalf("empty values changed: %+v", r.Args)
	}
}
