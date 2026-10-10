package storage

import (
	"context"
	"time"

	"wscan/internal/domain"
)

func (s *Store) CreateCredential(ctx context.Context, c domain.Credential) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO credentials(project_id,type,username,domain,secret,notes) VALUES(?,?,?,?,?,?)`,
		c.ProjectID, c.Type, c.Username, c.Domain, c.Secret, c.Notes)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListCredentials(ctx context.Context, projectID int64) ([]domain.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,project_id,type,username,domain,secret,notes FROM credentials WHERE project_id=? ORDER BY id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Credential
	for rows.Next() {
		var c domain.Credential
		if err = rows.Scan(&c.ID, &c.ProjectID, &c.Type, &c.Username, &c.Domain, &c.Secret, &c.Notes); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) UpdateCredential(ctx context.Context, c domain.Credential) error {
	_, err := s.db.ExecContext(ctx, `UPDATE credentials SET type=?,username=?,domain=?,secret=?,notes=? WHERE id=? AND project_id=?`, c.Type, c.Username, c.Domain, c.Secret, c.Notes, c.ID, c.ProjectID)
	return err
}

func (s *Store) DeleteCredential(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM credentials WHERE id=?`, id)
	return err
}

// RecordAttempt logs one login attempt for lockout-window tracking (see
// RecentFailureCount). Successes are recorded too, so a credential's full
// history — including the success that ended a spray against it — stays in
// one timeline.
func (s *Store) RecordAttempt(ctx context.Context, projectID int64, target, username, protocol string, success bool) error {
	n := 0
	if success {
		n = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO credential_attempts(project_id,target,username,protocol,success,attempted_at) VALUES(?,?,?,?,?,?)`,
		projectID, target, username, protocol, n, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// RecentFailureCount counts failed attempts against username across every
// target and protocol in this project since `since`. Deliberately not
// scoped to one host or protocol: a domain account's AD lockout counter is
// shared across every service that authenticates against the same DC (SMB,
// LDAP, WinRM, RDP, ...), so scoping the check more narrowly would undercount
// real lockout risk. Callers (the spray engine) use this to refuse an
// attempt before it is ever sent once the count reaches the project's
// configured threshold.
func (s *Store) RecentFailureCount(ctx context.Context, projectID int64, username string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM credential_attempts WHERE project_id=? AND username=? AND success=0 AND attempted_at >= ?`,
		projectID, username, since.UTC().Format(time.RFC3339Nano)).Scan(&n)
	return n, err
}
