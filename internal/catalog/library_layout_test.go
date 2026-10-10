package catalog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedTemplateLibrary(t *testing.T) {
	root := t.TempDir()
	folder := filepath.Join(root, "templates", "http")
	if err := os.MkdirAll(folder, 0700); err != nil {
		t.Fatal(err)
	}
	raw := []byte("id: library-example\ninfo:\n  name: Library example\n  author: test\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}'\n    matchers:\n      - type: status\n        status: [200]\n")
	if err := os.WriteFile(filepath.Join(folder, "example.yaml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	cat := NewWithLibrary(t.TempDir(), root)
	entries, err := cat.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "http/example.yaml" || !entries[0].Available {
		t.Fatalf("unexpected catalog: %+v", entries)
	}
	b, err := cat.Load(context.Background(), entries[0].Path)
	if err != nil || string(b) != string(raw) {
		t.Fatalf("load: %v", err)
	}
	// Missing files in an installed library must not silently come from upstream.
	if _, err := cat.Load(context.Background(), "http/missing.yaml"); err == nil {
		t.Fatal("missing template loaded")
	}
}
