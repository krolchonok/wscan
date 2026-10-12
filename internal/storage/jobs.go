package storage

import "context"

// Job snapshots contain metadata and sanitized events, never credentials or callbacks.
func (s *Store) SaveJob(ctx context.Context, id int, data []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO background_jobs(id,snapshot) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET snapshot=excluded.snapshot`, id, string(data))
	return err
}
func (s *Store) LoadJobs(ctx context.Context) ([][]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT snapshot FROM background_jobs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, []byte(s))
	}
	return out, rows.Err()
}
