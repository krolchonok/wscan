package js

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"wscan/internal/libsync"

	"github.com/dop251/goja"
)

// fsModule implements the real nuclei/fs surface (ListDir, ReadFile,
// ReadFileAsString, ReadFilesFromDir) — see
// github.com/projectdiscovery/nuclei/v3/pkg/js/libs/fs. Real nuclei permits
// only $HOME/nuclei-templates/*; we mirror that with root = our library's
// nuclei-templates directory, so a template's relative path (e.g.
// "helpers/payloads/cve-2023-34039-keys") resolves exactly where it lives in
// the library repo.
func fsModule(vm *goja.Runtime, libraryDir string) goja.Value {
	root := libsync.TemplateDir(libraryDir)
	obj := vm.NewObject()
	_ = obj.Set("ListDir", func(call goja.FunctionCall) goja.Value {
		path := call.Argument(0).String()
		itemType := ""
		if len(call.Arguments) > 1 {
			itemType = call.Argument(1).String()
		}
		names, err := fsListDir(root, path, itemType)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(names)
	})
	_ = obj.Set("ReadFile", func(call goja.FunctionCall) goja.Value {
		b, err := fsReadFile(root, call.Argument(0).String())
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(b)
	})
	_ = obj.Set("ReadFileAsString", func(call goja.FunctionCall) goja.Value {
		b, err := fsReadFile(root, call.Argument(0).String())
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		return vm.ToValue(string(b))
	})
	_ = obj.Set("ReadFilesFromDir", func(call goja.FunctionCall) goja.Value {
		dir := call.Argument(0).String()
		names, err := fsListDir(root, dir, "file")
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}
		contents := make([]string, 0, len(names))
		for _, name := range names {
			b, err := fsReadFile(root, dir+"/"+name)
			if err != nil {
				panic(vm.ToValue(err.Error()))
			}
			contents = append(contents, string(b))
		}
		return vm.ToValue(contents)
	})
	return obj
}

// fsResolve jails a template-relative path under root: filepath.Clean("/"+p)
// collapses any ".." against a leading "/" before it's ever joined onto
// root, so the result can never climb above root regardless of how many
// ".." segments the template supplies.
func fsResolve(root, path string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("fs: no library directory configured")
	}
	clean := filepath.Clean("/" + path)
	resolved := filepath.Join(root, clean)
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absResolved, err := filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	if absResolved != absRoot && !strings.HasPrefix(absResolved, absRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("fs: path escapes permitted directory: %s", path)
	}
	return absResolved, nil
}

func fsListDir(root, path, itemType string) ([]string, error) {
	resolved, err := fsResolve(root, path)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if itemType == "file" && e.IsDir() {
			continue
		}
		if itemType == "dir" && !e.IsDir() {
			continue
		}
		out = append(out, e.Name())
	}
	return out, nil
}

func fsReadFile(root, path string) ([]byte, error) {
	resolved, err := fsResolve(root, path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolved)
}
