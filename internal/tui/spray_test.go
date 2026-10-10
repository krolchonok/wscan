package tui

import (
	"testing"

	"wscan/internal/domain"
	"wscan/internal/engine"
)

func newTestModelForSpray(t *testing.T) model {
	t.Helper()
	m := newTestModelForSettings(t)
	m.current.AllowCredentialAttack = true
	if err := m.store.SetProjectScanSettings(m.ctx, m.current); err != nil {
		t.Fatal(err)
	}
	m.scanner = engine.New(m.store, engine.Config{TimeoutSeconds: 1})
	return m
}

func TestOpenSpraySetupRefusedWithoutAllowCredentialAttack(t *testing.T) {
	m := newTestModelForSpray(t)
	m.current.AllowCredentialAttack = false
	target := domain.Service{Host: "127.0.0.1", Port: 22, Protocol: "ssh"}

	m.openSpraySetup(target)
	if m.screen == "spray-setup" {
		t.Fatal("must not open spray-setup when AllowCredentialAttack is false")
	}
	if m.message == "" {
		t.Fatal("expected a message explaining why it was refused")
	}
}

func TestOpenSpraySetupRefusedWithoutCredentials(t *testing.T) {
	m := newTestModelForSpray(t)
	target := domain.Service{Host: "127.0.0.1", Port: 22, Protocol: "ssh"}

	m.openSpraySetup(target)
	if m.screen == "spray-setup" {
		t.Fatal("must not open spray-setup with zero saved credentials")
	}
	if m.message == "" {
		t.Fatal("expected a message pointing at the credentials screen")
	}
}

func TestSpraySetupCheckboxesAndSelectAllNone(t *testing.T) {
	m := newTestModelForSpray(t)
	id1, err := m.store.CreateCredential(m.ctx, domain.Credential{ProjectID: m.current.ID, Type: "password", Username: "a", Secret: "x"})
	if err != nil {
		t.Fatal(err)
	}
	id2, err := m.store.CreateCredential(m.ctx, domain.Credential{ProjectID: m.current.ID, Type: "password", Username: "b", Secret: "y"})
	if err != nil {
		t.Fatal(err)
	}
	target := domain.Service{Host: "127.0.0.1", Port: 22, Protocol: "ssh"}
	m.openSpraySetup(target)
	if m.screen != "spray-setup" {
		t.Fatalf("expected spray-setup, got %q (message=%q)", m.screen, m.message)
	}

	got, _ := m.updateSpraySetup(" ")
	m = got.(model)
	if !m.sprayChecked[id1] || m.sprayChecked[id2] {
		t.Fatalf("space must toggle only the focused row, got %v", m.sprayChecked)
	}

	got, _ = m.updateSpraySetup("a")
	m = got.(model)
	if !m.sprayChecked[id1] || !m.sprayChecked[id2] {
		t.Fatal("'a' must select every credential")
	}

	got, _ = m.updateSpraySetup("n")
	m = got.(model)
	if m.sprayChecked[id1] || m.sprayChecked[id2] {
		t.Fatal("'n' must clear every selection")
	}
}

func TestSpraySetupEnterWithNoSelectionStaysOnSetup(t *testing.T) {
	m := newTestModelForSpray(t)
	_, err := m.store.CreateCredential(m.ctx, domain.Credential{ProjectID: m.current.ID, Type: "password", Username: "a", Secret: "x"})
	if err != nil {
		t.Fatal(err)
	}
	target := domain.Service{Host: "127.0.0.1", Port: 22, Protocol: "ssh"}
	m.openSpraySetup(target)

	got, cmd := m.updateSpraySetup("enter")
	m = got.(model)
	if m.screen != "spray-setup" {
		t.Fatalf("enter with nothing checked must stay on spray-setup, got %q", m.screen)
	}
	if cmd != nil {
		t.Fatal("enter with nothing checked must not launch a command")
	}
}

// TestSpraySetupEnterRunsAndProducesSprayDone exercises the actual wiring
// from the TUI into engine.SprayCredentials: a closed port makes the
// attempt itself fail, but the point here is that runSprayCmd's tea.Cmd
// reaches the engine and comes back as a well-formed sprayDone — the
// success/failure path within the engine is already covered by
// internal/engine's own tests (TestSprayCredentialsEndToEndAgainstRealSSHServer).
func TestSpraySetupEnterRunsAndProducesSprayDone(t *testing.T) {
	m := newTestModelForSpray(t)
	_, err := m.store.CreateCredential(m.ctx, domain.Credential{ProjectID: m.current.ID, Type: "password", Username: "a", Secret: "x"})
	if err != nil {
		t.Fatal(err)
	}
	target := domain.Service{Host: "127.0.0.1", Port: 1, Protocol: "ssh"}
	m.openSpraySetup(target)

	got, _ := m.updateSpraySetup(" ")
	m = got.(model)
	got, cmd := m.updateSpraySetup("enter")
	m = got.(model)
	if m.screen != "spray-running" {
		t.Fatalf("enter with a selection must move to spray-running, got %q", m.screen)
	}
	if cmd == nil {
		t.Fatal("expected a tea.Cmd to be returned")
	}
	if len(m.spraySelectedCreds) != 1 {
		t.Fatalf("expected the checked credential to be captured, got %d", len(m.spraySelectedCreds))
	}

	msg := cmd()
	done, ok := msg.(sprayDone)
	if !ok {
		t.Fatalf("expected a sprayDone message, got %T", msg)
	}
	if len(done.results) != 1 || done.results[0].Success {
		t.Fatalf("expected one failed attempt against a closed port, got %+v", done.results)
	}
}

func TestOpenModulePickerRequiresSuccess(t *testing.T) {
	m := newTestModelForSpray(t)
	m.sprayResults = []domain.AuthAttempt{{Username: "a", Protocol: "ssh", Success: false}}
	m.sprayTarget = &domain.Service{Host: "127.0.0.1", Port: 22, Protocol: "ssh"}

	got, _ := m.updateSprayResults("m")
	m2 := got.(model)
	if m2.screen == "spray-module-picker" {
		t.Fatal("module picker must not open for a failed attempt")
	}
}

func TestOpenModulePickerListsProtocolModules(t *testing.T) {
	m := newTestModelForSpray(t)
	m.sprayResults = []domain.AuthAttempt{{Username: "jdoe", Protocol: "ldap", Success: true}}
	m.sprayTarget = &domain.Service{Host: "127.0.0.1", Port: 389, Protocol: "ldap"}

	got, _ := m.updateSprayResults("m")
	m2 := got.(model)
	if m2.screen != "spray-module-picker" {
		t.Fatalf("expected spray-module-picker, got %q", m2.screen)
	}
	if len(m2.sprayModules) == 0 {
		t.Fatal("expected at least one ldap module")
	}
	for _, mod := range m2.sprayModules {
		if mod.Protocol != "ldap" {
			t.Fatalf("module picker must only list ldap modules, got %+v", mod)
		}
	}
}

// TestCredentialForAttemptMatchesByUsernameAndDomain locks in the lookup
// runSelectedModule depends on: AuthAttempt never carries Secret, so the
// module runner must recover the real credential from the
// spraySelectedCreds captured at launch time.
func TestCredentialForAttemptMatchesByUsernameAndDomain(t *testing.T) {
	m := newTestModelForSpray(t)
	m.spraySelectedCreds = []domain.Credential{
		{Username: "jdoe", Domain: "CORP", Secret: "s1"},
		{Username: "jdoe", Domain: "", Secret: "s2"},
	}
	got, ok := m.credentialForAttempt(domain.AuthAttempt{Username: "jdoe", Domain: "CORP"})
	if !ok || got.Secret != "s1" {
		t.Fatalf("expected the CORP\\jdoe credential, got ok=%v %+v", ok, got)
	}
	got, ok = m.credentialForAttempt(domain.AuthAttempt{Username: "jdoe", Domain: ""})
	if !ok || got.Secret != "s2" {
		t.Fatalf("expected the local jdoe credential, got ok=%v %+v", ok, got)
	}
	_, ok = m.credentialForAttempt(domain.AuthAttempt{Username: "nobody"})
	if ok {
		t.Fatal("expected no match for an unknown username")
	}
}
