package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditSeparatesCompatibilityFromTargetExecution(t *testing.T) {
	library := t.TempDir()
	dir := filepath.Join(library, "nuclei-templates", "http")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	good := `id: good
http:
 - path: ['{{BaseURL}}']
   matchers: [{type: status, status: [200]}]
`
	bad := `id: bad
javascript:
 - code: require("nuclei/oracle");
   matchers: [{type: dsl, dsl: ['success == true']}]
`
	for name, source := range map[string]string{"good.yaml": good, "bad.yaml": bad} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	if err := NewWithLibrary("", library).Audit(out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["mode"] != "native-offline" || fields["total"] != float64(2) || fields["native_compatible"] != float64(1) || fields["unavailable"] != float64(1) || fields["target_executions_verified"] != float64(0) {
		t.Fatalf("summary=%s", data)
	}
	readme, err := os.ReadFile(filepath.Join(out, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(readme), "--script-help") || !strings.Contains(string(readme), "Проверок на целях выполнено: **0**") {
		t.Fatalf("misleading audit: %s", readme)
	}
}
