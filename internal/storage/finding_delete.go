package storage

import (
	"context"
	"encoding/json"
	"strings"
	"time"
	"wscan/internal/domain"
)

// FindingKey identifies a detector at one endpoint, across repeated runs.
func FindingKey(f domain.Finding) string {
	return strings.Join([]string{f.Target, f.TemplateID, f.MatchedAt, f.MatcherName}, "\x00")
}
func FindingDeleteSnapshot(fs []domain.Finding) map[string]time.Time {
	out := map[string]time.Time{}
	for _, f := range fs {
		k := FindingKey(f)
		old, ok := out[k]
		if !ok || f.Time.After(old) {
			out[k] = f.Time
		}
	}
	return out
}
func FindingInDeleteSnapshot(f domain.Finding, snapshot map[string]time.Time) bool {
	cutoff, ok := snapshot[FindingKey(f)]
	return ok && !f.Time.After(cutoff)
}

// DeleteFindings removes saved copies visible at confirmation time, in this
// project only. Results created after the snapshot remain untouched.
func (s *Store) DeleteFindings(ctx context.Context, projectID int64, fs []domain.Finding) (int, error) {
	snapshot := FindingDeleteSnapshot(fs)
	if len(snapshot) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT f.id,f.data FROM findings f JOIN runs r ON r.id=f.run_id WHERE r.project_id=?`, projectID)
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		var raw string
		var f domain.Finding
		if err = rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return 0, err
		}
		if err = json.Unmarshal([]byte(raw), &f); err != nil {
			rows.Close()
			return 0, err
		}
		if FindingInDeleteSnapshot(f, snapshot) {
			ids = append(ids, id)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if _, err = tx.ExecContext(ctx, `DELETE FROM findings WHERE id=?`, id); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}
