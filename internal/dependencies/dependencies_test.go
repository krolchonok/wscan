package dependencies

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallPlans(t *testing.T) {
	tests := []struct {
		os, manager string
		index       int
		root        bool
		want        string
	}{
		{"linux", "apt-get", 0, false, "/bin/sudo /bin/apt-get install -y python3"},
		{"linux", "apt-get", 1, true, "/bin/apt-get install -y ruby"},
		{"linux", "dnf", 1, false, "/bin/sudo /bin/dnf install -y ruby"},
		{"linux", "pacman", 0, true, "/bin/pacman -S --needed --noconfirm python"},
		{"linux", "apk", 0, true, "/bin/apk add python3"},
		{"darwin", "brew", 1, false, "/bin/brew install ruby"},
		{"windows", "", 0, false, "https://www.python.org/downloads/windows/"},
		{"windows", "", 1, false, "https://rubyinstaller.org/downloads/"},
	}
	for _, tt := range tests {
		t.Run(tt.os+tt.manager+fmt.Sprint(tt.index), func(t *testing.T) {
			lookup := func(name string) (string, error) {
				if name == tt.manager || name == "sudo" {
					return "/bin/" + name, nil
				}
				return "", fmt.Errorf("absent")
			}
			plan, err := installPlan(tt.os, tt.index, lookup, tt.root)
			if err != nil || plan.Display() != tt.want {
				t.Fatalf("plan: %s %v", plan.Display(), err)
			}
		})
	}
}

func TestNoManagerAndMissingSudo(t *testing.T) {
	missing := func(string) (string, error) { return "", fmt.Errorf("absent") }
	plan, err := installPlan("linux", 0, missing, false)
	if err != nil || plan.URL == "" {
		t.Fatal("missing package manager must offer official download")
	}
	lookup := func(name string) (string, error) {
		if name == "apt-get" {
			return "/bin/apt-get", nil
		}
		return missing(name)
	}
	if _, err := installPlan("linux", 0, lookup, false); err == nil {
		t.Fatal("missing sudo silently ignored")
	}
	if _, err := installPlan("linux", 2, missing, false); err == nil {
		t.Fatal("invalid interpreter accepted")
	}
}

func TestInspectInterpreters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	root := t.TempDir()
	t.Setenv("PATH", root)
	for name, output := range map[string]string{"python3": "Python 3.12.0", "ruby": "ruby 3.3.0"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("#!/bin/sh\nprintf '%s\\n' '"+output+"'\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	status := Inspect(context.Background())
	if !status[0].Installed() || !strings.Contains(status[0].Version, "3.12") || !status[1].Installed() {
		t.Fatalf("status: %+v", status)
	}
}

func TestInspectRejectsPython2(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	root := t.TempDir()
	t.Setenv("PATH", root)
	if err := os.WriteFile(filepath.Join(root, "python"), []byte("#!/bin/sh\nprintf 'Python 2.7.0\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	status := Inspect(context.Background())
	if status[0].Installed() || status[1].Installed() {
		t.Fatalf("bad versions accepted: %+v", status)
	}
}
