package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedLibraryPayloadAndWorkflow(t *testing.T) {
	root := t.TempDir()
	folder := filepath.Join(root, "templates", "helpers")
	if err := os.MkdirAll(folder, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "words.txt"), []byte("alpha\nbeta\n"), 0600); err != nil {
		t.Fatal(err)
	}
	words, err := readPayloadFile(root, "http/example.yaml", "helpers/words.txt")
	if err != nil || len(words) != 2 || words[1] != "beta" {
		t.Fatalf("payload: %v %v", words, err)
	}
	raw := []byte("id: workflow-child\ninfo:\n  name: Child\n  severity: info\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: status\n        status: [200]\n")
	if err := os.WriteFile(filepath.Join(root, "templates", "child.yaml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	e := New(nil, Config{LibraryDir: root})
	tmpl, err := e.loadTemplate("child.yaml")
	if err != nil || tmpl.ID != "workflow-child" {
		t.Fatalf("workflow child: %v %v", tmpl.ID, err)
	}
}
