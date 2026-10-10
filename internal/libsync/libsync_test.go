package libsync

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func fixtureRepo(t *testing.T, valid bool) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "templates")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	name := "check.yaml"
	if !valid {
		name = "readme.md"
	}
	if err := os.WriteFile(filepath.Join(path, name), []byte("id: example\ninfo:\n  name: Example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-b", "main"}, {"add", "."}, {"-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %v %s", err, out)
		}
	}
	return root
}

func TestDownloadAndFailedUpdatePreserveLibrary(t *testing.T) {
	t.Setenv("WSCAN_LIBRARY_DIR", "")
	t.Setenv("WSCAN_LIBRARY_URL", "")
	t.Setenv("WSCAN_LIBRARY_REF", "")
	app := t.TempDir()
	cfg, err := UpdateContext(context.Background(), app, fixtureRepo(t, true), "main")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Commit == "" || cfg.UpdatedAt == "" {
		t.Fatal("missing installed version/date")
	}
	status, err := Inspect(app)
	if err != nil || !status.Installed || status.Templates != 1 {
		t.Fatalf("status: %+v %v", status, err)
	}
	original, err := os.ReadFile(configPath(app))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateContext(context.Background(), app, fixtureRepo(t, false), "main"); err == nil {
		t.Fatal("invalid library accepted")
	}
	after, err := os.ReadFile(configPath(app))
	if err != nil || string(after) != string(original) {
		t.Fatal("failed download changed saved config")
	}
	if _, err := os.Stat(filepath.Join(cfg.Path, "templates", "check.yaml")); err != nil {
		t.Fatal("installed template lost")
	}
	if _, err := UpdateContext(context.Background(), app, cfg.URL, "missing-branch"); err == nil {
		t.Fatal("missing branch accepted")
	}
	status, err = Inspect(app)
	if err != nil || !status.Installed {
		t.Fatal("download failure lost installation")
	}
}

func TestStatusAbsentAndLegacyLayout(t *testing.T) {
	t.Setenv("WSCAN_LIBRARY_DIR", "")
	t.Setenv("WSCAN_LIBRARY_URL", "")
	app := t.TempDir()
	status, err := Inspect(app)
	if err != nil || status.Installed {
		t.Fatalf("unexpected status: %+v %v", status, err)
	}
	dir := filepath.Join(DefaultDir(app), "nuclei-templates")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "example.yml"), []byte("id: example"), 0600); err != nil {
		t.Fatal(err)
	}
	if TemplateDir(DefaultDir(app)) != dir {
		t.Fatal("legacy folder not detected")
	}
	status, err = Inspect(app)
	if err != nil || !status.Installed || status.Templates != 1 {
		t.Fatalf("unexpected legacy status: %+v %v", status, err)
	}
}
