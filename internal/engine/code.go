package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"wscan/internal/domain"
	"wscan/internal/template"
)

// codeInterpExt maps common nuclei code: engine names to the file extension
// their interpreter is most conventionally invoked with. Not required for
// correctness (most interpreters don't care), but matches nuclei's own
// behavior and avoids surprising an interpreter that does care (e.g. some
// shells pick a dialect from the extension).
var codeInterpExt = map[string]string{
	"py": ".py", "python": ".py", "python3": ".py",
	"rb": ".rb", "ruby": ".rb",
	"sh": ".sh", "bash": ".sh",
	"ps1": ".ps1", "powershell": ".ps1", "pwsh": ".ps1",
	"pl": ".pl", "perl": ".pl",
	"php": ".php",
	"js":  ".js", "node": ".js",
}

func codeFileExt(interpreterPath string) string {
	name := strings.ToLower(filepath.Base(interpreterPath))
	name = strings.TrimSuffix(name, filepath.Ext(name)) // strip .exe on windows
	if ext, ok := codeInterpExt[name]; ok {
		return ext
	}
	return ".txt"
}

// execCode runs one code: request through a real external interpreter on
// the scanner's own machine. This is the one request type that steps
// outside the "only our own engine" principle on purpose: every other
// protocol (http/tcp/network/dns/ssl/flow) runs entirely inside our own
// process. Because of that, it only ever runs when the caller has
// explicitly opted in (allowCodeExec) — never implied by the template
// itself being well-formed or Compatible.
func execCode(ctx context.Context, t domain.Template, req domain.CodeRequest, target string, vars map[string]any, tvars map[string]string, allowCodeExec bool, timeout time.Duration) ([]domain.Finding, []error) {
	if !allowCodeExec {
		return nil, nil
	}
	interp := template.FindInterpreter(req.Engine)
	if interp == "" {
		return nil, []error{fmt.Errorf("%s: no interpreter found on this machine (tried: %s)", t.ID, strings.Join(req.Engine, ", "))}
	}

	source := applyTargetVars(render(req.Source, vars), tvars)
	tmp, err := os.CreateTemp("", "wscan-code-*"+codeFileExt(interp))
	if err != nil {
		return nil, []error{fmt.Errorf("%s: %w", t.ID, err)}
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	_, writeErr := tmp.WriteString(source)
	closeErr := tmp.Close()
	if writeErr != nil {
		return nil, []error{fmt.Errorf("%s: write script: %w", t.ID, writeErr)}
	}
	if closeErr != nil {
		return nil, []error{fmt.Errorf("%s: write script: %w", t.ID, closeErr)}
	}

	args := make([]string, 0, len(req.Args)+1)
	args = append(args, tmpPath)
	for _, a := range req.Args {
		args = append(args, applyTargetVars(render(a, vars), tvars))
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, interp, args...)
	// No inherited stdin/environment beyond what exec.Command already
	// restricts to (the scanner process's own env) — the script gets
	// exactly the rendered source and args, nothing more to key off of.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	configureProcessGroup(cmd)      // kill the whole process group on timeout, not just the direct child (code_unix.go / code_other.go)
	cmd.WaitDelay = 2 * time.Second // backstop: force Wait() to return even if some descendant keeps a pipe open
	runErr := cmd.Run()

	output := stdout.String()
	env := map[string]any{"response": output, "stdout": output, "stderr": stderr.String()}
	for k, v := range vars {
		if _, ok := env[k]; !ok {
			env[k] = v
		}
	}
	extra := runExtractors(req.Extractors, env, nil, nil, []byte(output))
	matched, evidence := matchOrExtract(req.Matchers, req.MatchersCondition, 0, nil, []byte(output), env, extra)

	var errs []error
	if runErr != nil {
		// A non-zero exit or interpreter error is still worth surfacing even
		// when matchers happen to pass on whatever partial output came out,
		// but it must never block a genuine match from being reported.
		errs = append(errs, fmt.Errorf("%s: %s: %w", t.ID, interp, runErr))
	}
	if !matched {
		return nil, errs
	}
	if matchersOnlyInternal(req.Matchers) {
		return nil, errs
	}
	return []domain.Finding{{
		TemplateID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity,
		Target: target, MatchedAt: "code://" + filepath.Base(interp), Evidence: evidence,
		Risk: t.Risk, Protocol: "code", Time: time.Now().UTC(),
	}}, errs
}
