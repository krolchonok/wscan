package js

import (
	"github.com/dop251/goja"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedLibraryJSFiles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "templates", "helpers")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.bin"), []byte("fixture-key"), 0600); err != nil {
		t.Fatal(err)
	}
	vm := goja.New()
	if err := vm.Set("files", fsModule(vm, root)); err != nil {
		t.Fatal(err)
	}
	value, err := vm.RunString(`files.ReadFileAsString("helpers/key.bin")`)
	if err != nil || value.String() != "fixture-key" {
		t.Fatalf("file dependency: %v %v", value, err)
	}
}
