package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAuditCLIHelpDoesNotOpenDatabase(t *testing.T) {
	for _, run := range []func([]string) error{runAuditCLI, runADScanCLI, runLocalSMBCLI} {
		if err := run([]string{"--help"}); err != nil {
			t.Fatal(err)
		}
	}
}
func TestAuditCLIRequiresExplicitSecret(t *testing.T) {
	t.Setenv("WSCAN_AUDIT_PASSWORD", "")
	t.Setenv("WSCAN_AUDIT_NTHASH", "")
	if err := runAuditCLI([]string{"--mode", "windows", "--host", "127.0.0.1", "--username", "admin", "--port", "389"}); err == nil {
		t.Fatal("invalid WinRM port accepted")
	}
	if err := runLocalSMBCLI([]string{"--targets", "127.0.0.1", "--username", "CORP\\admin", "--max-failures", "0"}); err == nil {
		t.Fatal("unlimited local failures accepted")
	}
}
func TestAuditOutputDoesNotOverwriteAndIsPrivate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "result.json")
	if err := writeAuditJSON(p, map[string]string{"state": "observed"}); err != nil {
		t.Fatal(err)
	}
	if err := writeAuditJSON(p, "replace"); err == nil {
		t.Fatal("report overwritten")
	}
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "observed") {
		t.Fatal(string(b), err)
	}
	s, err := os.Stat(p)
	if err != nil {
		t.Fatal(s, err)
	}
	// Windows uses ACLs rather than Unix permission bits.
	if runtime.GOOS != "windows" && s.Mode().Perm() != 0600 {
		t.Fatal(s.Mode())
	}
}

func TestKerberosCLIValidationBeforeNetwork(t *testing.T) {
	for _, args := range [][]string{
		{"--mode", "kerberoast", "--host", "127.0.0.1", "--domain", "lab.local"},
		{"--mode", "asrep", "--host", "127.0.0.1", "--domain", "lab.local", "--rps", "0"},
		{"--mode", "asrep", "--host", "127.0.0.1", "--domain", "lab.local", "--users", "alice", "--users-file", "missing"},
		{"--mode", "kerberoast", "--host", "127.0.0.1", "--domain", "lab.local", "--username", "alice", "--tgs-etypes", "3"},
		{"--mode", "kerberoast", "--host", "127.0.0.1", "--domain", "lab.local", "--nopreauth-user", "legacy"},
		{"--mode", "kerberoast", "--host", "127.0.0.1", "--domain", "lab.local", "--nopreauth-user", "legacy", "--tgt-file", "ticket.kirbi"},
		{"--mode", "kerberoast", "--host", "127.0.0.1", "--domain", "lab.local", "--nopreauth-user", "legacy", "--username", "alice"},
		{"--mode", "asrep", "--host", "127.0.0.1", "--domain", "lab.local", "--nopreauth-user", "legacy"},
	} {
		if e := runAuditCLI(args); e == nil {
			t.Fatal("invalid request accepted", args)
		}
	}
	p := filepath.Join(t.TempDir(), "names.txt")
	if e := os.WriteFile(p, []byte("alice\n\nbob\n"), 0600); e != nil {
		t.Fatal(e)
	}
	values, e := auditList("", p, 2)
	if e != nil || len(values) != 2 {
		t.Fatal(values, e)
	}
	if _, e = auditList("", p, 1); e == nil {
		t.Fatal("file limit ignored")
	}
}
