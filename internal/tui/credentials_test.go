package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/catalog"
	"wscan/internal/domain"
)

func enterKey() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }

func newTestModelForCredentials(t *testing.T) model {
	t.Helper()
	m := newTestModelForSettings(t)
	m.openCredentials()
	return m
}

func TestOpenCredentialsStartsEmpty(t *testing.T) {
	m := newTestModelForCredentials(t)
	if m.screen != "credentials" {
		t.Fatalf("screen = %q, want credentials", m.screen)
	}
	if len(m.credentials) != 0 {
		t.Fatalf("new project must start with 0 credentials, got %d", len(m.credentials))
	}
}

// TestAddCredentialWizardFullFlow walks the whole a → type → username →
// domain → secret → notes sequence and checks the result lands in storage
// with every field intact, including an empty (optional) domain.
func TestAddCredentialWizardFullFlow(t *testing.T) {
	m := newTestModelForCredentials(t)

	got, _ := m.updateCredentials("a")
	m = got.(model)
	if m.screen != "cred-add-type" {
		t.Fatalf("screen = %q, want cred-add-type", m.screen)
	}
	if m.credNewType != "password" {
		t.Fatalf("default type = %q, want password", m.credNewType)
	}

	got, _ = m.updateCredAddType("right")
	m = got.(model)
	if m.credNewType != "ntlm-hash" {
		t.Fatalf("toggling type = %q, want ntlm-hash", m.credNewType)
	}

	got, _ = m.updateCredAddType("enter")
	m = got.(model)
	if m.screen != "input" || m.inputAction != "cred-username" {
		t.Fatalf("enter on type picker must start username input, got screen=%q action=%q", m.screen, m.inputAction)
	}

	m.input = "jdoe"
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.credNewUsername != "jdoe" {
		t.Fatalf("username not captured, got %q", m.credNewUsername)
	}
	if m.inputAction != "cred-domain" {
		t.Fatalf("after username must move to cred-domain, got %q", m.inputAction)
	}

	// Leave domain empty — a local (non-AD) account.
	m.input = ""
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.credNewDomain != "" {
		t.Fatalf("expected empty domain, got %q", m.credNewDomain)
	}
	if m.inputAction != "cred-secret" {
		t.Fatalf("after domain must move to cred-secret, got %q", m.inputAction)
	}

	m.input = "31d6cfe0d16ae931b73c59d7e0c089c0"
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.credNewSecret != "31d6cfe0d16ae931b73c59d7e0c089c0" {
		t.Fatalf("secret not captured, got %q", m.credNewSecret)
	}
	if m.inputAction != "cred-notes" {
		t.Fatalf("after secret must move to cred-notes, got %q", m.inputAction)
	}

	m.input = "found via LAPS"
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.screen != "credentials" {
		t.Fatalf("after notes must land back on credentials, got %q", m.screen)
	}
	if len(m.credentials) != 1 {
		t.Fatalf("expected 1 saved credential, got %d", len(m.credentials))
	}
	c := m.credentials[0]
	if c.Type != "ntlm-hash" || c.Username != "jdoe" || c.Domain != "" || c.Secret != "31d6cfe0d16ae931b73c59d7e0c089c0" || c.Notes != "found via LAPS" {
		t.Fatalf("saved credential mismatch: %+v", c)
	}
}

// TestAddCredentialWizardAllowsAnonymousNullSession reproduces nxc's
// `smb -u ” -p ”`: the wizard must accept an empty username AND an empty
// secret, since that blank pair is the anonymous/null-session identity
// itself, not "nothing entered".
func TestAddCredentialWizardAllowsAnonymousNullSession(t *testing.T) {
	m := newTestModelForCredentials(t)

	got, _ := m.updateCredentials("a")
	m = got.(model)
	got, _ = m.updateCredAddType("enter")
	m = got.(model)

	m.input = ""
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.inputAction != "cred-domain" {
		t.Fatalf("empty username must be accepted, expected to move to cred-domain, got action=%q screen=%q", m.inputAction, m.screen)
	}

	m.input = ""
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.inputAction != "cred-secret" {
		t.Fatalf("expected to move to cred-secret, got %q", m.inputAction)
	}

	m.input = ""
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.inputAction != "cred-notes" {
		t.Fatalf("empty secret must be accepted, expected to move to cred-notes, got action=%q", m.inputAction)
	}

	m.input = "null session sweep"
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.screen != "credentials" || len(m.credentials) != 1 {
		t.Fatalf("expected the anonymous credential to be saved, screen=%q count=%d", m.screen, len(m.credentials))
	}
	c := m.credentials[0]
	if c.Username != "" || c.Secret != "" {
		t.Fatalf("expected blank username/secret, got %+v", c)
	}
}

// TestGuestShortcutCreatesAnonymousCredentialInOneStep is the one-keystroke
// path: 'g' on the credentials screen must save a blank-username/password
// credential directly, with no wizard prompts at all.
func TestGuestShortcutCreatesAnonymousCredentialInOneStep(t *testing.T) {
	m := newTestModelForCredentials(t)

	got, _ := m.updateCredentials("g")
	m = got.(model)
	if m.screen != "credentials" {
		t.Fatalf("g must not open any wizard screen, got %q", m.screen)
	}
	if len(m.credentials) != 1 {
		t.Fatalf("expected 1 credential after g, got %d", len(m.credentials))
	}
	c := m.credentials[0]
	if c.Username != "" || c.Secret != "" || c.Domain != "" {
		t.Fatalf("expected a fully blank anonymous credential, got %+v", c)
	}
	if credIdentLabel(c) != "(anonymous / null session)" {
		t.Fatalf("credIdentLabel = %q, want the anonymous label", credIdentLabel(c))
	}
}

// TestDeleteCredentialRequiresConfirmation locks in that d opens a confirm
// screen rather than deleting immediately, and that Esc cancels without
// deleting while Enter actually removes it from storage.
func TestDeleteCredentialRequiresConfirmation(t *testing.T) {
	m := newTestModelForCredentials(t)
	id, err := m.store.CreateCredential(m.ctx, testCredential(m))
	if err != nil {
		t.Fatal(err)
	}
	m.openCredentials()
	if len(m.credentials) != 1 {
		t.Fatalf("expected 1 credential before delete, got %d", len(m.credentials))
	}

	got, _ := m.updateCredentials("d")
	m2 := got.(model)
	if m2.screen != "cred-delete-confirm" {
		t.Fatalf("d must open the confirm screen, got %q", m2.screen)
	}
	if m2.credDeleteID != id {
		t.Fatalf("credDeleteID = %d, want %d", m2.credDeleteID, id)
	}

	cancelled, _ := m2.updateCredDeleteConfirm("esc")
	m3 := cancelled.(model)
	if m3.screen != "credentials" {
		t.Fatalf("esc must cancel back to credentials, got %q", m3.screen)
	}
	stillThere, err := m3.store.ListCredentials(m3.ctx, m3.current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stillThere) != 1 {
		t.Fatalf("esc must not delete anything, got %d credentials", len(stillThere))
	}

	confirmed, _ := m2.updateCredDeleteConfirm("enter")
	m4 := confirmed.(model)
	if m4.screen != "credentials" {
		t.Fatalf("confirming must return to credentials, got %q", m4.screen)
	}
	if len(m4.credentials) != 0 {
		t.Fatalf("expected 0 credentials after confirmed delete, got %d", len(m4.credentials))
	}
}

func testCredential(m model) domain.Credential {
	return domain.Credential{
		ProjectID: m.current.ID,
		Type:      "password",
		Username:  "asmith",
		Secret:    "hunter2",
	}
}

func TestEditCredentialKeepsIDAndPrefillsFields(t *testing.T) {
	m := newTestModelForCredentials(t)
	id, err := m.store.CreateCredential(m.ctx, domain.Credential{ProjectID: m.current.ID, Type: "password", Username: "svc", Domain: "WRONG", Secret: "old", Notes: "keep"})
	if err != nil {
		t.Fatal(err)
	}
	m.openCredentials()
	got, _ := m.updateCredentials("e")
	m = got.(model)
	got, _ = m.updateCredAddType("enter")
	m = got.(model)
	if m.input != "svc" {
		t.Fatal("username not prefilled")
	}
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.input != "WRONG" {
		t.Fatal("domain not prefilled")
	}
	m.input = "ARCHETYPE"
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.input != "old" {
		t.Fatal("secret not prefilled")
	}
	m.input = " visible password "
	if !strings.Contains(m.viewInput(100), " visible password ") {
		t.Fatal("secret masked")
	}
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if m.input != "keep" {
		t.Fatal("notes not prefilled")
	}
	got, _ = m.updateInput(enterKey())
	m = got.(model)
	if len(m.credentials) != 1 {
		t.Fatal("edit created duplicate")
	}
	c := m.credentials[0]
	if c.ID != id || c.Domain != "ARCHETYPE" || c.Secret != " visible password " || c.Notes != "keep" {
		t.Fatal("edit did not preserve fields")
	}
	got, _ = m.updateCredentials("e")
	m = got.(model)
	got, _ = m.updateCredAddType("enter")
	m = got.(model)
	m.input = "discard"
	got, _ = m.updateInput(tea.KeyMsg{Type: tea.KeyEsc})
	m = got.(model)
	got, _ = m.updateCredAddType("esc")
	m = got.(model)
	m.openCredentials()
	if m.credentials[0].Username != "svc" {
		t.Fatal("cancel changed storage")
	}
}

func TestMSSQLConnectReloadsEditedCredential(t *testing.T) {
	m := newTestModelForCredentials(t)
	m.cat = catalog.New(t.TempDir())
	c := domain.Credential{ProjectID: m.current.ID, Type: "password", Username: "svc", Domain: "OLD", Secret: "old"}
	id, err := m.store.CreateCredential(m.ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	c.ID = id
	m.screen = "mssql-setup"
	m.mssqlConsole.credentials = []domain.Credential{c}
	c.Domain = "ARCHETYPE"
	c.Secret = "new"
	if err = m.store.UpdateCredential(m.ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ := m.updateMSSQL("enter")
	m = got.(model)
	if m.mssqlConsole.options.Domain != "ARCHETYPE" || m.mssqlConsole.options.Password != "new" {
		t.Fatal("connect retained outdated credentials")
	}
}
