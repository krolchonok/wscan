package tui

import (
	"strings"
	"testing"
)

// Enabling AllowCredentialAttack must route through a confirmation screen,
// not flip immediately — same risk-weight pattern as AllowCodeExec/
// AllowExploit (see settings.go's toggleAllowCredentialAttack).
func TestAllowCredentialAttackRequiresConfirmation(t *testing.T) {
	m := newTestModelForSettings(t)
	m.settingsIndex = settingAllowCredAttack
	if m.current.AllowCredentialAttack {
		t.Fatal("new project must default to AllowCredentialAttack=false")
	}

	got, _ := m.updateSettings("enter")
	m2 := got.(model)
	if m2.screen != "credential-attack-confirm" {
		t.Fatalf("enabling must open the confirm screen, got screen=%q", m2.screen)
	}
	if m2.current.AllowCredentialAttack {
		t.Fatal("must not be enabled yet — only after confirming")
	}

	cancelled, _ := m2.updateCredentialAttackConfirm("esc")
	m3 := cancelled.(model)
	if m3.screen != "settings" || m3.current.AllowCredentialAttack {
		t.Fatalf("esc must cancel back to settings with AllowCredentialAttack still false, got screen=%q allow=%v", m3.screen, m3.current.AllowCredentialAttack)
	}

	confirmed, _ := m2.updateCredentialAttackConfirm("enter")
	m4 := confirmed.(model)
	if m4.screen != "settings" || !m4.current.AllowCredentialAttack {
		t.Fatalf("enter must confirm and enable, got screen=%q allow=%v", m4.screen, m4.current.AllowCredentialAttack)
	}
	reloaded, err := m4.store.ListProjects(m4.ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range reloaded {
		if p.ID == m4.current.ID {
			found = true
			if !p.AllowCredentialAttack {
				t.Fatal("AllowCredentialAttack was not persisted to storage")
			}
		}
	}
	if !found {
		t.Fatal("project not found after confirm")
	}
}

func TestAllowCredentialAttackDisableNeedsNoConfirmation(t *testing.T) {
	m := newTestModelForSettings(t)
	m.settingsIndex = settingAllowCredAttack
	m.current.AllowCredentialAttack = true

	got, _ := m.updateSettings("enter")
	m2 := got.(model)
	if m2.screen == "credential-attack-confirm" {
		t.Fatal("disabling must not open the confirm screen")
	}
	if m2.current.AllowCredentialAttack {
		t.Fatal("disabling must take effect immediately")
	}
}

// TestLockoutSettingsZeroMeansDefaultNotUnlimited locks in the settings
// screen's display contract: 0 must render as "use the default", not a bare
// "0" that could read as "disabled" — see lockoutValueDisplay.
func TestLockoutSettingsZeroMeansDefaultNotUnlimited(t *testing.T) {
	m := newTestModelForSettings(t)
	rows := m.settingRows()
	got := rows[settingLockoutMaxAttempts]
	if !strings.Contains(got, "по умолчанию") {
		t.Fatalf("lockout max-attempts row with value 0 must show the default, got %q", got)
	}
	got = rows[settingLockoutWindow]
	if !strings.Contains(got, "по умолчанию") {
		t.Fatalf("lockout window row with value 0 must show the default, got %q", got)
	}
}

// TestSaveLockoutSettingAllowsZero reproduces that 0 is a valid, savable
// value for the lockout fields (unlike every other numeric setting, where 0
// is rejected) — see saveSettingValue's minimum-value branch.
func TestSaveLockoutSettingAllowsZero(t *testing.T) {
	m := newTestModelForSettings(t)
	m.settingsIndex = settingLockoutMaxAttempts
	got, _ := m.saveSettingValue("0")
	m2 := got.(model)
	if strings.Contains(m2.message, "Введи целое число") {
		t.Fatalf("0 must be accepted for the lockout max-attempts setting, got message %q", m2.message)
	}
	if m2.current.LockoutMaxAttempts != 0 {
		t.Fatalf("LockoutMaxAttempts = %d, want 0", m2.current.LockoutMaxAttempts)
	}
}
