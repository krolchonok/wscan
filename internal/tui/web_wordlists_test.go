package tui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecListsPickerAndDefault(t *testing.T) {
	dir := t.TempDir()
	root := secListsWebRoots(dir)[0]
	for name := range map[string]bool{"common.txt": true, "raft-small-files.txt": true, "nested/custom.txt": true, "README.md": true} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("admin\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	choices := secListsWordlists(dir)
	var managed []webWordlistChoice
	for _, c := range choices {
		if c.path == "" || filepath.Dir(c.path) == root || filepath.Dir(c.path) == filepath.Join(root, "nested") {
			managed = append(managed, c)
		}
	}
	if len(managed) != 4 || managed[1].name != "common.txt" || managed[2].name != "raft-small-files.txt" {
		t.Fatalf("%+v", managed)
	}
	if got := defaultWebWordlist(dir); got != filepath.Join(root, "common.txt") {
		t.Fatal(got)
	}
	m := model{appDir: dir, screen: "web-discovery"}
	got, _ := m.openWebWordlists()
	m = got.(model)
	m.webDiscovery.wordlistFilter = "custom"
	got, _ = m.updateWebWordlists("enter")
	m = got.(model)
	if m.screen != "web-discovery" || m.webDiscovery.options.Wordlist != filepath.Join(root, "nested", "custom.txt") {
		t.Fatal("selection failed")
	}
}
func TestSecListsManualPathAndEmptyFilter(t *testing.T) {
	m := model{screen: "web-wordlists", webDiscovery: webDiscoveryState{wordlistFilter: "old"}}
	m.startInput("web-wordlist-filter")
	got, _ := m.updateInput(enterKey())
	m = got.(model)
	if m.screen != "web-wordlists" || m.webDiscovery.wordlistFilter != "" {
		t.Fatal("empty filter rejected")
	}
	m.startInput("web-discovery-wordlist")
	m.input = "/tmp/my-list.txt"
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.screen != "web-discovery" || m.webDiscovery.options.Wordlist != "/tmp/my-list.txt" {
		t.Fatal("manual path not applied")
	}
}
