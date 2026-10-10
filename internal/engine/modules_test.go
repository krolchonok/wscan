package engine

import (
	"context"
	"testing"

	"wscan/internal/domain"
)

func TestRunModuleRefusedWithoutAllowCredentialAttack(t *testing.T) {
	e := New(&fakeStore{}, Config{TimeoutSeconds: 1})
	_, err := e.RunModule(context.Background(), domain.Project{ID: 1}, domain.Service{Host: "127.0.0.1", Protocol: "smb"}, domain.Credential{Username: "jdoe"}, "smb-shares", nil)
	if err == nil {
		t.Fatal("expected an error when AllowCredentialAttack is false")
	}
}

func TestRunModuleRejectsUnknownModuleName(t *testing.T) {
	e := New(&fakeStore{}, Config{TimeoutSeconds: 1})
	p := domain.Project{ID: 1, AllowCredentialAttack: true}
	_, err := e.RunModule(context.Background(), p, domain.Service{Host: "127.0.0.1", Protocol: "smb"}, domain.Credential{Username: "jdoe"}, "does-not-exist", nil)
	if err == nil {
		t.Fatal("expected an error for an unknown module name")
	}
}

func TestRunModuleRecordsFailureForLockoutAccounting(t *testing.T) {
	store := &fakeStore{}
	e := New(store, Config{TimeoutSeconds: 1})
	p := domain.Project{ID: 1, AllowCredentialAttack: true}
	// A closed port makes the module call itself fail — the point here is
	// that RunModule still feeds that failure into the same lockout ledger
	// SprayCredentials uses (RecordAttempt), not that smb-shares succeeds.
	target := domain.Service{Host: "127.0.0.1", Port: 1, Protocol: "smb"}
	cred := domain.Credential{Username: "jdoe", Secret: "x"}

	res, err := e.RunModule(context.Background(), p, target, cred, "smb-shares", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Error == "" {
		t.Fatal("expected the module result to carry the dial error")
	}
	if store.failureCounts["jdoe"] != 1 {
		t.Fatalf("RunModule must record a failure for lockout accounting, got count %d", store.failureCounts["jdoe"])
	}
}

func TestWinRMExecRequiresCommandArgument(t *testing.T) {
	e := New(&fakeStore{}, Config{TimeoutSeconds: 1})
	p := domain.Project{ID: 1, AllowCredentialAttack: true}
	target := domain.Service{Host: "127.0.0.1", Port: 1, Protocol: "winrm"}
	cred := domain.Credential{Username: "jdoe", Secret: "x"}

	res, err := e.RunModule(context.Background(), p, target, cred, "winrm-exec", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Error == "" {
		t.Fatal(`expected an error when args["command"] is missing`)
	}
}

func TestAvailableModulesFiltersByProtocol(t *testing.T) {
	all := AvailableModules("")
	if len(all) != len(moduleCatalog) {
		t.Fatalf("AvailableModules(\"\") = %d, want %d (the full catalog)", len(all), len(moduleCatalog))
	}
	ldapOnly := AvailableModules("ldap")
	if len(ldapOnly) == 0 {
		t.Fatal("expected at least one ldap module")
	}
	for _, m := range ldapOnly {
		if m.Protocol != "ldap" {
			t.Fatalf("AvailableModules(\"ldap\") returned a non-ldap module: %+v", m)
		}
	}
	none := AvailableModules("carrier-pigeon")
	if len(none) != 0 {
		t.Fatalf("AvailableModules for an unknown protocol = %d, want 0", len(none))
	}
}

// TestModuleCatalogIndexMatchesCatalog locks in that every entry listed in
// moduleCatalog (what the TUI/discovery shows) has a matching dispatchable
// function in moduleCatalogIndex, and vice versa — a drift here would mean
// either a module that's advertised but errors as "unknown module", or one
// that works but is invisible to discovery.
func TestModuleCatalogIndexMatchesCatalog(t *testing.T) {
	for _, m := range moduleCatalog {
		if _, ok := moduleCatalogIndex[m.Name]; !ok {
			t.Errorf("module %q is listed in moduleCatalog but has no entry in moduleCatalogIndex", m.Name)
		}
	}
	for name := range moduleCatalogIndex {
		found := false
		for _, m := range moduleCatalog {
			if m.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("module %q is dispatchable but missing from moduleCatalog", name)
		}
	}
}
