package template

import (
	"fmt"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// LocalTemplateReason excludes checks of the scanner's OS/files from the
// catalog for remote host and port assessments.
func LocalTemplateReason(source []byte, path string) string {
	path = strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	if strings.HasPrefix(path, "cloud/") || strings.HasPrefix(path, "code/linux/") || strings.HasPrefix(path, "code/macos/") || strings.HasPrefix(path, "code/privilege-escalation/") || path == "code/windows/enumeration/unquoted-service-paths.yaml" || path == "code/windows/enumeration/weak-service-binary-permissions.yaml" || strings.HasPrefix(path, "file/") || strings.Contains(path, "/audit/") && strings.HasPrefix(path, "code/") {
		return "Локальный аудит ОС или файлов не входит в проверки удалённых сервисов"
	}
	var root map[string]any
	if yaml.Unmarshal(source, &root) != nil {
		return ""
	}
	if local, _ := root["self-contained"].(bool); local {
		return "Локальная проверка self-contained не входит в проверки выбранного хоста/порта"
	}
	if root["file"] != nil {
		return "Проверка локальных файлов не входит в сетевой скан"
	}
	info, _ := root["info"].(map[string]any)
	for _, tag := range strings.FieldsFunc(strings.ToLower(fmt.Sprint(info["tags"])), func(r rune) bool {
		return r == ',' || r == ' ' || r == '[' || r == ']'
	}) {
		if tag == "windows-audit" || tag == "linux-audit" || tag == "local-audit" || tag == "os-audit" {
			return "Локальный аудит ОС не входит в проверки удалённых сервисов"
		}
	}
	return ""
}

// NetworkTemplateReason checks local scope and, for code: templates,
// whether any of the interpreters the template lists is actually installed
// on this scanner machine. It does not execute code or probe a target —
// "available" here only means "could run here", not "is allowed to run":
// that second gate is the operator's own, explicit, per-project
// engine.Config.AllowCodeExec (see internal/engine/code.go) — code:
// templates shell out to a real interpreter on the scanner's own machine,
// unlike every other request type, so running one is never implied by it
// merely showing up as available in the catalog.
func NetworkTemplateReason(source []byte) string {
	if reason := LocalTemplateReason(source, ""); reason != "" {
		return reason
	}
	var root struct {
		SelfContained bool `yaml:"self-contained"`
		Code          []struct {
			Engine []string `yaml:"engine"`
		} `yaml:"code"`
	}
	if yaml.Unmarshal(source, &root) != nil {
		return ""
	}
	if root.SelfContained {
		return "Локальная проверка self-contained выполняется на машине сканера, а не на выбранном хосте/порту"
	}
	for _, request := range root.Code {
		if len(request.Engine) == 0 {
			continue
		}
		if FindInterpreter(request.Engine) == "" {
			return fmt.Sprintf("Интерпретатор для code не найден на машине сканера (пробовали: %s)", strings.Join(request.Engine, ", "))
		}
	}
	return ""
}

// FindInterpreter returns the path of the first listed interpreter found on
// PATH, or "" if none of them are installed. nuclei's code: engine list is
// ordered by preference (e.g. ["py", "python3"]), so first match wins.
func FindInterpreter(engines []string) string {
	for _, name := range engines {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}
