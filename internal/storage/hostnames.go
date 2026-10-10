package storage

import (
	"context"
	"encoding/json"
	"time"
)

type HostNameCache struct {
	Server    string
	Names     []string
	CheckedAt time.Time
}

// HostNames returns explicit PTR discoveries and the one-hour system DNS cache.
func (s *Store) HostNames(ctx context.Context, projectID int64) (map[string]HostNameCache, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT host,names,queried_at,dns_server FROM host_names WHERE project_id=? AND (dns_server!='' OR queried_at>=?)`, projectID, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]HostNameCache)
	for rows.Next() {
		var host, data, queriedAt, server string
		if err := rows.Scan(&host, &data, &queriedAt, &server); err != nil {
			return nil, err
		}
		var names []string
		if err := json.Unmarshal([]byte(data), &names); err != nil {
			return nil, err
		}
		checkedAt, err := time.Parse(time.RFC3339Nano, queriedAt)
		if err != nil {
			return nil, err
		}
		result[host] = HostNameCache{Names: names, CheckedAt: checkedAt, Server: server}
	}
	return result, rows.Err()
}

func (s *Store) SaveHostNames(ctx context.Context, projectID int64, names map[string][]string) error {
	return s.saveHostNames(ctx, projectID, names, "")
}

// SavePTRHostNames preserves explicit DNS discoveries until the next PTR scan.
func (s *Store) SavePTRHostNames(ctx context.Context, projectID int64, names map[string][]string, server string) error {
	return s.saveHostNames(ctx, projectID, names, server)
}

func (s *Store) saveHostNames(ctx context.Context, projectID int64, names map[string][]string, server string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queriedAt := time.Now().UTC().Format(time.RFC3339Nano)
	for host, values := range names {
		data, err := json.Marshal(values)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO host_names(project_id,host,names,queried_at,dns_server) VALUES(?,?,?,?,?) ON CONFLICT(project_id,host) DO UPDATE SET names=excluded.names,queried_at=excluded.queried_at,dns_server=excluded.dns_server WHERE host_names.dns_server='' OR excluded.dns_server!=''`, projectID, host, string(data), queriedAt, server); err != nil {
			return err
		}
	}
	return tx.Commit()
}
