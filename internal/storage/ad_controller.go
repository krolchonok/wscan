package storage

import (
	"context"
	"database/sql"
	"errors"
)

// A manual controller is an operator preference, not a discovered/confirmed role.
func (s *Store) ADController(ctx context.Context, projectID int64) (host, domain string, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT host,domain FROM ad_controller_selection WHERE project_id=?", projectID).Scan(&host, &domain)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}

func (s *Store) SetADController(ctx context.Context, projectID int64, host, domain string) error {
	if host == "" {
		_, err := s.db.ExecContext(ctx, "DELETE FROM ad_controller_selection WHERE project_id=?", projectID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO ad_controller_selection(project_id,host,domain) VALUES(?,?,?) ON CONFLICT(project_id) DO UPDATE SET host=excluded.host,domain=excluded.domain`, projectID, host, domain)
	return err
}
