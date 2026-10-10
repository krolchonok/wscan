package tui

import (
	"strings"
	"testing"

	"wscan/internal/domain"
)

func TestSavedSMTPFailureIsClassifiedAsError(t *testing.T) {
	f := domain.Finding{TemplateID: "nmap/smtp-commands", Name: "smtp-commands", Severity: "info", Evidence: "Couldn't establish connection on port 25"}
	if resultClass(f) != "Ошибка" || !strings.Contains(resultLabel(f), "[Ошибка]") {
		t.Fatalf("historical failure is shown as a finding: %s", resultLabel(f))
	}
	if counts := resultCounts([]domain.Finding{f}); counts != "Риски: 0 · Сведения: 0 · Ошибки: 1" {
		t.Fatalf("wrong counts: %s", counts)
	}
}
