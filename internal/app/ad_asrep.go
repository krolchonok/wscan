package app

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"wscan/internal/adscan"
	"wscan/internal/domain"
	"wscan/internal/engine"
)

func (m Worker) runADASREP(ctx context.Context, details adscan.Result, projectID, runID int64, emit Reporter) engine.Result {
	opts, skipped := adscan.ASREPReconOptions(details)
	r := engine.Result{Skipped: skipped}
	for _, message := range skipped {
		if emit != nil {
			emit(message)
		}
	}
	for _, o := range opts {
		o.RPS = m.current.RPS
		o.Timeout = time.Duration(m.current.TimeoutSeconds) * time.Second
		if m.adExportDir != "" {
			o.ExportDir = filepath.Join(m.adExportDir, fmt.Sprintf("project-%d-run-%d", projectID, runID))
		}
		if emit != nil {
			o.Progress = func(s string) { emit(s) }
		}
		report, err := adscan.RunAccess(ctx, o)
		if err != nil {
			r.Errors = append(r.Errors, o.Domain+": "+err.Error())
		}
		r.Findings = append(r.Findings, asrepReportFindings(report)...)
		for _, check := range report.Checks {
			if check.State == "error" || check.State == "incomplete" {
				r.Errors = append(r.Errors, o.Domain+" · "+check.Name+": "+check.Evidence)
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	return r
}

func asrepReportFindings(report adscan.AccessReport) []domain.Finding {
	findings := report.Findings()
	// Only confirmed vulnerabilities/errors become individual rows; normal
	// pre-auth/account-not-found replies remain in a compact coverage summary.
	var out []domain.Finding
	negative, denied, confirmed := 0, 0, 0
	var valid, disabled []string
	endpoint := report.Endpoint
	if endpoint == "" {
		endpoint = "tcp://" + net.JoinHostPort(report.Host, "88")
	}
	errors := 0
	attempted := 0
	for i, check := range report.Checks {
		if strings.HasPrefix(check.ID, "asrep/") {
			attempted++
		}
		switch check.State {
		case "valid":
			valid = append(valid, strings.TrimPrefix(check.ID, "asrep/"))
			continue
		case "valid-disabled":
			disabled = append(disabled, strings.TrimPrefix(check.ID, "asrep/"))
			continue
		case "negative":
			negative++
			continue
		case "denied":
			denied++
			continue
		case "confirmed":
			confirmed++
		case "error":
			errors++
		}
		f := findings[i]
		f.Protocol, f.MatchedAt = "kerberos", endpoint
		if check.State == "confirmed" {
			f.Risk = "AS-REP без pre-auth получен; это не подтверждает знание пароля или вход по TGT."
		}
		out = append(out, f)
	}
	if len(report.Checks) > 0 {
		out = append(out, domain.Finding{TemplateID: "ad-access/asrep-summary", Name: "Kerberos user-enum и AS-REP без пароля", Severity: "info", Target: report.Host, MatchedAt: endpoint, Protocol: "kerberos", MatcherName: "observed", Evidence: fmt.Sprintf("Проверено имён: %d · существующие с pre-auth: %d · отключённые/заблокированные: %d · AS-REP: %d · не существуют: %d · прочий отказ KDC: %d · ошибки: %d", attempted, len(valid), len(disabled), confirmed, negative, denied, errors), Time: time.Now().UTC()})
	}
	if len(valid)+len(disabled) > 0 {
		parts := make([]string, 0, 2)
		if len(valid) > 0 {
			parts = append(parts, "существуют и требуют pre-auth: "+strings.Join(valid, ", "))
		}
		if len(disabled) > 0 {
			parts = append(parts, "существуют, но отключены/заблокированы: "+strings.Join(disabled, ", "))
		}
		out = append(out, domain.Finding{TemplateID: "ad-access/kerberos-users", Name: "Kerberos подтвердил имена пользователей", Severity: "info", Target: report.Host, MatchedAt: endpoint, Protocol: "kerberos", MatcherName: "observed", Evidence: strings.Join(parts, "\n"), Risk: "Проверка различий ответов KDC без пароля; успешный вход не выполнялся.", Time: time.Now().UTC()})
	}
	if len(report.Artifacts) > 0 {
		out = append(out, domain.Finding{TemplateID: "ad-access/asrep-artifacts", Name: "Артефакты AS-REP", Severity: "info", Target: report.Host, MatchedAt: endpoint, Protocol: "kerberos", Evidence: strings.Join(report.Artifacts, "\n"), Time: time.Now().UTC()})
	}
	return out
}

func ASREPReportFindings(report adscan.AccessReport) []domain.Finding {
	return asrepReportFindings(report)
}
