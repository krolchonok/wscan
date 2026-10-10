package libsync

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Config describes where the scanner pulls its check library from.
type Config struct {
	URL       string `json:"url"`
	Ref       string `json:"ref"` // branch or tag; default main
	Path      string `json:"path"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Commit    string `json:"commit,omitempty"`
}

const remoteFile = "library-remote.json"

// DefaultRepositoryURL points to the separate repository that distributes templates.
const DefaultRepositoryURL = "https://github.com/krolchonok/wscan-templates.git"

// DefaultDir is ~/.config/wscan/library (or $WSCAN_LIBRARY_DIR).
func DefaultDir(appDir string) string {
	if v := strings.TrimSpace(os.Getenv("WSCAN_LIBRARY_DIR")); v != "" {
		return v
	}
	return filepath.Join(appDir, "library")
}

func configPath(appDir string) string {
	return filepath.Join(appDir, remoteFile)
}

// LoadConfig reads the saved remote settings.
func LoadConfig(appDir string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(configPath(appDir))
	if err != nil {
		if os.IsNotExist(err) {
			cfg.URL = envOr("WSCAN_LIBRARY_URL", DefaultRepositoryURL)
			cfg.Ref = envOr("WSCAN_LIBRARY_REF", "main")
			cfg.Path = DefaultDir(appDir)
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Ref == "" {
		cfg.Ref = "main"
	}
	if cfg.Path == "" {
		cfg.Path = DefaultDir(appDir)
	}
	if cfg.URL == "" {
		cfg.URL = DefaultRepositoryURL
	}
	if u := strings.TrimSpace(os.Getenv("WSCAN_LIBRARY_URL")); u != "" {
		cfg.URL = u
	}
	return cfg, nil
}

func SaveConfig(appDir string, cfg Config) error {
	if cfg.Ref == "" {
		cfg.Ref = "main"
	}
	if cfg.Path == "" {
		cfg.Path = DefaultDir(appDir)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(appDir, ".library-config-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(append(data, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), configPath(appDir))
}

// TemplateDir supports the published templates/ layout and older local libraries.
func TemplateDir(dir string) string {
	for _, name := range []string{"templates", "nuclei-templates"} {
		path := filepath.Join(dir, name)
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			return path
		}
	}
	return filepath.Join(dir, "templates")
}

type Status struct {
	Config    Config
	Installed bool
	Templates int
	Files     int
	Bytes     int64
}

func Inspect(appDir string) (Status, error) {
	cfg, err := LoadConfig(appDir)
	status := Status{Config: cfg}
	if err != nil {
		return status, err
	}
	root := TemplateDir(cfg.Path)
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return status, nil
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		status.Files++
		status.Bytes += info.Size()
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			status.Templates++
		}
		return nil
	})
	status.Installed = err == nil && status.Templates > 0
	return status, err
}

func Update(appDir, url, ref string) (Config, error) {
	return UpdateContext(context.Background(), appDir, url, ref)
}

// UpdateContext validates a fresh checkout before replacing the installed copy.
func UpdateContext(ctx context.Context, appDir, url, ref string) (Config, error) {
	cfg, err := LoadConfig(appDir)
	if err != nil {
		return cfg, err
	}
	if url != "" {
		cfg.URL = url
	}
	if ref != "" {
		cfg.Ref = ref
	}
	if cfg.Ref == "" {
		cfg.Ref = "main"
	}
	if _, err := exec.LookPath("git"); err != nil {
		return cfg, fmt.Errorf("для скачивания библиотеки установите git")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o755); err != nil {
		return cfg, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(cfg.Path), ".library-download-")
	if err != nil {
		return cfg, err
	}
	defer os.RemoveAll(stage)
	if err := runGitContext(ctx, "", "clone", "--depth", "1", "--single-branch", "--branch", cfg.Ref, "--", cfg.URL, stage); err != nil {
		return cfg, err
	}
	if err := verifyLibrary(stage); err != nil {
		return cfg, err
	}
	if err := ctx.Err(); err != nil {
		return cfg, err
	}
	cfg.Commit = gitOutput(stage, "rev-parse", "HEAD")
	cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	backup := stage + "-previous"
	hadPrevious := false
	if _, err := os.Stat(cfg.Path); err == nil {
		if err := os.Rename(cfg.Path, backup); err != nil {
			return cfg, err
		}
		hadPrevious = true
	} else if !os.IsNotExist(err) {
		return cfg, err
	}
	if err := os.Rename(stage, cfg.Path); err != nil {
		if hadPrevious {
			_ = os.Rename(backup, cfg.Path)
		}
		return cfg, err
	}
	if err := SaveConfig(appDir, cfg); err != nil {
		_ = os.Rename(cfg.Path, stage)
		if hadPrevious {
			_ = os.Rename(backup, cfg.Path)
		}
		return cfg, err
	}
	if hadPrevious {
		_ = os.RemoveAll(backup)
	}
	return cfg, nil
}

func verifyLibrary(dir string) error {
	root := TemplateDir(dir)
	found := false
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && (strings.HasSuffix(strings.ToLower(path), ".yaml") || strings.HasSuffix(strings.ToLower(path), ".yml")) {
			found = true
		}
		return nil
	})
	if err != nil || !found {
		return fmt.Errorf("в репозитории нет папки templates с YAML-шаблонами")
	}
	return nil
}

func runGitContext(ctx context.Context, dir string, args ...string) error {
	gitArgs := []string{"-c", "credential.interactive=false"}
	cmd := exec.CommandContext(ctx, "git", append(gitArgs, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=Never")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("не удалось скачать библиотеку: %v\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func gitOutput(dir string, args ...string) string {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
