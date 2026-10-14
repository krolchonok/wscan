package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"wscan/internal/app"
)

func (m *model) addSharedJob(s app.Job) *job {
	if j := m.jobByID(s.ID); j != nil {
		return j
	}
	id := s.ID
	j := &job{id: id, projectID: s.ProjectID, kind: s.Kind, label: s.Label, targets: append([]string(nil), s.Targets...), scope: s.Scope, status: statusRunning, started: s.Started, options: append([]string(nil), s.Options...), checks: append([]string(nil), s.Checks...), cancel: func() { _ = m.shared.Jobs.Cancel(id) }}
	m.jobSeq = max(m.jobSeq, id)
	// Restored snapshots arrive newest first; keep the TUI list in numeric
	// order and retain the selected task when an older snapshot is inserted.
	count := len(m.jobs)
	index := sort.Search(count, func(i int) bool { return m.jobs[i].id >= id })
	m.jobs = append(m.jobs, nil)
	copy(m.jobs[index+1:], m.jobs[index:count])
	m.jobs[index] = j
	if m.jobIndex >= 0 && m.jobIndex < count && index <= m.jobIndex {
		m.jobIndex++
	}
	return j
}
func (m *model) syncSharedJobs() {
	if m.shared == nil {
		return
	}
	for _, snapshot := range m.shared.Jobs.List() {
		if m.hiddenSharedJobs[snapshot.ID] {
			continue
		}
		j := m.addSharedJob(snapshot)
		if j.sharedRevision == snapshot.Revision {
			continue
		}
		j.sharedRevision = snapshot.Revision
		j.scope = snapshot.Scope
		j.checkErrors = nil
		if snapshot.CheckErrors != nil {
			j.checkErrors = append([]string{}, snapshot.CheckErrors...)
		}
		j.options = append([]string(nil), snapshot.Options...)
		j.environment = append([]string(nil), snapshot.Environment...)
		j.failureStage = snapshot.FailureStage
		j.journalDropped = snapshot.JournalDropped
		j.checks = append([]string(nil), snapshot.Checks...)
		if snapshot.Status == "running" || snapshot.Status == "cancelling" {
			m.applyJobEvent(jobEvent{id: j.id, stage: snapshot.Stage, completed: snapshot.Completed, total: snapshot.Total, hasProgress: true})
			continue
		}
		if j.sharedTerminal {
			continue
		}
		j.sharedTerminal = true
		if snapshot.Outcome != nil {
			outcome := snapshot.Outcome
			var err error
			if snapshot.Status == "cancelled" {
				err = context.Canceled
			} else if snapshot.Status == "failed" {
				err = fmt.Errorf("%s", snapshot.Error)
			}
			ev := jobEvent{id: j.id, done: true, result: outcome.Result, adResult: outcome.AD, err: err}
			if snapshot.Source == m.jobSource() {
				ev.projectID, ev.projectName = outcome.ProjectID, outcome.ProjectName
			} else {
				j.projectID = snapshot.ProjectID
			}
			m.applyJobEvent(ev)
		} else {
			j.projectID = snapshot.ProjectID
			j.status = snapshot.Status
			if j.status == "interrupted" {
				j.status = statusFailed
			}
			j.stage = snapshot.Stage
			j.errText = snapshot.Error
			j.runID = snapshot.RunID
			j.findings = snapshot.Findings
			j.ended = snapshot.Ended
		}
		// Restore the complete service journal even after reconnecting or restarting.
		j.journal = nil
		for _, ev := range snapshot.Journal {
			j.journal = append(j.journal, ev.Time.Format("15:04:05")+"  "+ev.Message)
		}
		// Older snapshots only recorded the terminal stage, hiding the cause.
		if j.errText != "" {
			found := false
			for _, line := range j.journal {
				if strings.Contains(line, j.errText) {
					found = true
					break
				}
			}
			if !found {
				j.journal = append(j.journal, j.ended.Format("15:04:05")+"  Причина остановки: "+j.errText)
			}
		}
		if snapshot.PersistenceError != "" {
			j.addLog("Ошибка сохранения задачи: " + snapshot.PersistenceError)
		}
	}
	if err := m.reload(); err == nil && m.current.ID != 0 {
		found := false
		for _, p := range m.projects {
			if p.ID == m.current.ID {
				found = true
				break
			}
		}
		if !found {
			m.current.ID = 0
			m.screen = "projects"
			m.message = "Проект удалён в другом интерфейсе"
		}
	}
}

func (m model) jobSource() string {
	if m.clientSource != "" {
		return m.clientSource
	}
	return "tui"
}
