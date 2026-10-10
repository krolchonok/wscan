package storage

import "context"

// DeleteProject removes the project and all its database records atomically.
func (s *Store) DeleteProject(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, query := range []string{
		`DELETE FROM runs WHERE project_id=?`,
		`DELETE FROM inventory_exclusions WHERE project_id=?`,
		`DELETE FROM inventory_resets WHERE project_id=?`,
		`DELETE FROM projects WHERE id=?`,
	} {
		if _, err := tx.ExecContext(ctx, query, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
