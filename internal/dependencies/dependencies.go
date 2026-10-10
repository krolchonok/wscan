// Package dependencies detects optional interpreters and prepares OS installers.
package dependencies

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Interpreter struct {
	Name    string
	Path    string
	Version string
	Error   string
}

func (i Interpreter) Installed() bool { return i.Path != "" && i.Version != "" }

func Inspect(ctx context.Context) []Interpreter {
	result := []Interpreter{{Name: "Python 3"}, {Name: "Ruby"}}
	for i := range result {
		candidates := []string{"ruby"}
		if i == 0 {
			candidates = []string{"python3", "python", "py"}
		}
		for _, name := range candidates {
			path, err := exec.LookPath(name)
			if err != nil {
				continue
			}
			args := []string{"--version"}
			if name == "py" {
				args = []string{"-3", "--version"}
			}
			check, cancel := context.WithTimeout(ctx, 4*time.Second)
			output, err := exec.CommandContext(check, path, args...).CombinedOutput()
			cancel()
			if err != nil {
				result[i].Error = fmt.Sprintf("не удалось проверить %s: %v", name, err)
				continue
			}
			version := strings.TrimSpace(string(output))
			version, _, _ = strings.Cut(version, "\n")
			if i == 0 && !strings.HasPrefix(version, "Python 3.") {
				result[i].Error = "Нужен Python версии 3"
				continue
			}
			result[i].Path = path
			result[i].Version = version
			result[i].Error = ""
			break
		}
	}
	return result
}

type Plan struct {
	Name string
	Args []string
	URL  string
}

func (p Plan) Display() string {
	if p.URL != "" {
		return p.URL
	}
	return strings.Join(p.Args, " ")
}

func InstallPlan(index int) (Plan, error) {
	return installPlan(runtime.GOOS, index, exec.LookPath, os.Geteuid() == 0)
}

func installPlan(goos string, index int, lookup func(string) (string, error), root bool) (Plan, error) {
	if index < 0 || index > 1 {
		return Plan{}, fmt.Errorf("неизвестный интерпретатор")
	}
	name := "Python 3"
	pkg := "python3"
	url := "https://www.python.org/downloads/"
	if index == 1 {
		name = "Ruby"
		pkg = "ruby"
		url = "https://www.ruby-lang.org/en/documentation/installation/"
	}
	plan := Plan{Name: name}
	switch goos {
	case "linux":
		managers := []struct {
			name string
			args []string
		}{
			{"apt-get", []string{"install", "-y", pkg}},
			{"dnf", []string{"install", "-y", pkg}},
			{"yum", []string{"install", "-y", pkg}},
			{"pacman", []string{"-S", "--needed", "--noconfirm", map[bool]string{true: "ruby", false: "python"}[index == 1]}},
			{"zypper", []string{"--non-interactive", "install", pkg}},
			{"apk", []string{"add", pkg}},
		}
		for _, manager := range managers {
			path, err := lookup(manager.name)
			if err != nil {
				continue
			}
			plan.Args = append([]string{path}, manager.args...)
			if !root {
				sudo, err := lookup("sudo")
				if err != nil {
					return Plan{}, fmt.Errorf("для установки нужен sudo; установите %s вручную", name)
				}
				plan.Args = append([]string{sudo}, plan.Args...)
			}
			return plan, nil
		}
	case "darwin":
		if path, err := lookup("brew"); err == nil {
			if index == 0 {
				pkg = "python"
			}
			return Plan{Name: name, Args: []string{path, "install", pkg}}, nil
		}
	case "windows":
		url = "https://www.python.org/downloads/windows/"
		if index == 1 {
			url = "https://rubyinstaller.org/downloads/"
		}
	}
	plan.URL = url
	return plan, nil
}

func (p Plan) Command() (*exec.Cmd, error) {
	if len(p.Args) > 0 {
		return exec.Command(p.Args[0], p.Args[1:]...), nil
	}
	if p.URL == "" {
		return nil, fmt.Errorf("способ установки не выбран")
	}
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", p.URL)
	case "darwin":
		command = exec.Command("open", p.URL)
	default:
		command = exec.Command("xdg-open", p.URL)
	}
	if _, err := exec.LookPath(command.Args[0]); err != nil {
		return nil, fmt.Errorf("откройте страницу установки в браузере: %s", p.URL)
	}
	return command, nil
}
