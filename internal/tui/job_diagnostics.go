package tui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"wscan/internal/app"
)

func (m model) exportJobDiagnostics(j *job) (string, error) {
	snapshot := app.Job{ID: j.id, JobRequest: app.JobRequest{ProjectID: j.projectID, Kind: j.kind, Label: j.label, Targets: j.targets, Scope: j.scope, Source: m.jobSource(), Checks: j.checks, Options: j.options}, Status: j.status, Stage: j.stage, Error: j.errText, CheckErrors: j.taskErrors(), Started: j.started, Ended: j.ended, RunID: j.runID, Environment: j.environment, JournalDropped: j.journalDropped}
	for _, line := range j.journal {
		snapshot.Journal = append(snapshot.Journal, app.JobEvent{Message: line})
	}
	snapshot.FailureStage = j.failureStage
	if m.shared != nil {
		if saved, ok := m.shared.Jobs.Get(j.id); ok {
			snapshot = saved
		}
	}
	var secrets []string
	if m.store != nil {
		creds, err := m.store.ListCredentials(m.ctx, snapshot.ProjectID)
		if err != nil {
			return "", fmt.Errorf("не удалось подготовить маскирование секретов: %w", err)
		}
		for _, cred := range creds {
			secrets = append(secrets, cred.Secret)
		}
	}
	dir := filepath.Join(m.appDir, "reports")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, fmt.Sprintf("diagnostics-job-%d-*.txt", j.id))
	if err != nil {
		return "", err
	}
	name := f.Name()
	_, err = io.WriteString(f, app.JobDiagnostics(snapshot, secrets))
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}
