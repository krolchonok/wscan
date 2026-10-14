package app

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

// BuildVersion is set by the entry point before starting workers.
var BuildVersion = "dev"

var binaryIdentity struct {
	sync.Once
	value string
}

// CaptureDiagnostics records the scanner machine at launch, not at export time.
// It performs no network requests and does not collect arguments or environment.
func CaptureDiagnostics() []string {
	lines := []string{"wscan=" + BuildVersion, "os=" + runtime.GOOS + " arch=" + runtime.GOARCH + " go=" + runtime.Version()}
	if host, err := os.Hostname(); err == nil {
		lines = append(lines, "scanner_host="+host)
	}
	binaryIdentity.Do(func() {
		path, err := os.Executable()
		if err != nil {
			return
		}
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err == nil {
			binaryIdentity.value = fmt.Sprintf("binary_sha256=%x", h.Sum(nil))
		}
	})
	if binaryIdentity.value != "" {
		lines = append(lines, binaryIdentity.value)
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" || setting.Key == "vcs.time" || setting.Key == "vcs.modified" {
				lines = append(lines, setting.Key+"="+setting.Value)
			}
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		lines = append(lines, "interfaces_error="+err.Error())
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			lines = append(lines, "interface="+iface.Name+" error="+err.Error())
		}
		for _, address := range addresses {
			lines = append(lines, "interface="+iface.Name+" address="+address.String())
		}
	}
	return lines
}

var diagnosticKerberosHash = regexp.MustCompile(`\$krb5(?:asrep|tgs)\$[^\s]+`)
var diagnosticURLPassword = regexp.MustCompile(`(://[^\s/:@]+:)[^\s/@]+(@)`)

// JobDiagnostics contains no findings, objects, credentials or authentication
// material. Known project secrets are also removed from arbitrary error text.
func JobDiagnostics(j Job, secrets []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "WSCAN DIAGNOSTICS v1\nexported_at=%s\njob_id=%d project_id=%d run_id=%d\nkind=%s source=%s\nlabel=%s\nscope=%s\nstatus=%s stage=%s\nstarted_at=%s\nended_at=%s\nprogress=%d/%d\n",
		time.Now().UTC().Format(time.RFC3339Nano), j.ID, j.ProjectID, j.RunID, j.Kind, j.Source, j.Label, j.Scope, j.Status, j.Stage, diagnosticTime(j.Started), diagnosticTime(j.Ended), j.Completed, j.Total)
	if len(j.Environment) == 0 {
		b.WriteString("\nSCANNER AT LAUNCH\nNot recorded by this older build.\n")
	} else {
		b.WriteString("\nSCANNER AT LAUNCH\n" + strings.Join(j.Environment, "\n") + "\n")
	}
	b.WriteString("\nTARGETS\n" + strings.Join(j.Targets, "\n") + "\n\nOPTIONS\n" + strings.Join(j.Options, "\n") + "\n\nCHECKS\n" + strings.Join(j.Checks, "\n") + "\n")
	fmt.Fprintf(&b, "\nFAILURE\nfailure_stage=%s\n%s\n\nCHECK ERRORS (%d)\n", j.FailureStage, j.Error, len(j.CheckErrors))
	for i, message := range j.CheckErrors {
		fmt.Fprintf(&b, "%d. %s\n", i+1, message)
	}
	if j.PersistenceError != "" {
		fmt.Fprintf(&b, "\nPERSISTENCE ERROR\n%s\n", j.PersistenceError)
	}
	fmt.Fprintf(&b, "\nJOURNAL (%d events, %d earlier events dropped)\n", len(j.Journal), j.JournalDropped)
	for _, event := range j.Journal {
		fmt.Fprintf(&b, "%s seq=%d %s\n", diagnosticTime(event.Time), event.Sequence, event.Message)
	}
	text := b.String()
	// Replace longer secrets first when one secret contains another.
	secrets = append([]string(nil), secrets...)
	sort.Slice(secrets, func(i, k int) bool { return len(secrets[i]) > len(secrets[k]) })
	for _, secret := range secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[REDACTED]")
		}
	}
	text = diagnosticKerberosHash.ReplaceAllString(text, "[KERBEROS HASH REDACTED]")
	return diagnosticURLPassword.ReplaceAllString(text, "${1}[REDACTED]${2}")
}

func diagnosticTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339Nano)
}
