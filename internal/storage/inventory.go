package storage

import (
	"context"
	"encoding/json"
)

type InventoryExclusion struct{ Host, ServiceKey string }

type InventoryReset struct {
	Host       string
	ThroughRun int64
	Aliases    []string
}

func (s *Store) InventoryResets(ctx context.Context, projectID int64) ([]InventoryReset, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT host,through_run,aliases FROM inventory_resets WHERE project_id=?", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InventoryReset
	for rows.Next() {
		var r InventoryReset
		var raw string
		if err := rows.Scan(&r.Host, &r.ThroughRun, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &r.Aliases); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) InventoryExclusions(ctx context.Context, projectID int64) ([]InventoryExclusion, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT host,service_key FROM inventory_exclusions WHERE project_id=?", projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InventoryExclusion
	for rows.Next() {
		var e InventoryExclusion
		if err := rows.Scan(&e.Host, &e.ServiceKey); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ExcludeInventory(ctx context.Context, projectID int64, host, serviceKey string, targets, aliases []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if serviceKey == "" {
		raw, err := json.Marshal(aliases)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO inventory_resets(project_id,host,through_run,aliases) VALUES(?,?,(SELECT coalesce(max(id),0) FROM runs WHERE project_id=?),?) ON CONFLICT(project_id,host) DO UPDATE SET through_run=excluded.through_run,aliases=excluded.aliases`, projectID, host, projectID, string(raw)); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO inventory_exclusions(project_id,host,service_key) VALUES(?,?,?)", projectID, host, serviceKey); err != nil {
		return err
	}
	for _, target := range targets {
		if _, err = tx.ExecContext(ctx, "DELETE FROM targets WHERE project_id=? AND url=?", projectID, target); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RestoreInventoryHost(ctx context.Context, projectID int64, host string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM inventory_exclusions WHERE project_id=? AND host=?", projectID, host); err != nil {
		return err
	}
	// Re-adding a host must start empty: advance the reset watermark to the
	// current max run id so only scans after this restore appear on the desk.
	// Also clears a stale watermark left after run-history purge / id reuse.
	aliases, err := json.Marshal([]string{host})
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO inventory_resets(project_id,host,through_run,aliases) VALUES(?,?,(SELECT coalesce(max(id),0) FROM runs WHERE project_id=?),?)
		ON CONFLICT(project_id,host) DO UPDATE SET through_run=excluded.through_run,aliases=excluded.aliases`,
		projectID, host, projectID, string(aliases)); err != nil {
		return err
	}
	return tx.Commit()
}

// MaxRunID returns the highest run id for a project (0 if none).
func (s *Store) MaxRunID(ctx context.Context, projectID int64) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT coalesce(max(id),0) FROM runs WHERE project_id=?`, projectID).Scan(&n)
	return n, err
}
