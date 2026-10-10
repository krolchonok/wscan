package js

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type PGOptions struct {
	Host                                  string
	Port                                  int
	Username, Password, Database, SSLMode string
	Timeout                               time.Duration
}
type PGSession struct{ db *sql.DB }

func OpenPostgres(ctx context.Context, o PGOptions) (*PGSession, error) {
	if o.Database == "" {
		o.Database = "postgres"
	}
	if o.SSLMode == "" {
		o.SSLMode = "require"
	}
	u := &url.URL{Scheme: "postgres", User: url.UserPassword(o.Username, o.Password), Host: joinAddr(o.Host, o.Port), Path: "/" + o.Database}
	q := u.Query()
	q.Set("sslmode", o.SSLMode)
	q.Set("connect_timeout", fmt.Sprint(max(1, int(o.Timeout.Seconds()))))
	q.Set("default_transaction_read_only", "on")
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &PGSession{db: db}, nil
}
func (s *PGSession) Close() { s.db.Close() }

// Read executes one query inside a read-only transaction and always rolls it back.
func (s *PGSession) Read(ctx context.Context, query string) (map[string]any, error) {
	fields := strings.Fields(query)
	if len(fields) == 0 || (strings.ToUpper(fields[0]) != "SELECT" && strings.ToUpper(fields[0]) != "WITH" && strings.ToUpper(fields[0]) != "EXPLAIN") {
		return nil, fmt.Errorf("доступны SELECT, WITH и EXPLAIN")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	data := [][]any{}
	truncated := false
	for rows.Next() {
		if len(data) == 500 {
			truncated = true
			break
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		data = append(data, vals)
	}
	return map[string]any{"ResultSets": []map[string]any{{"Columns": cols, "Rows": data, "Count": len(data), "Truncated": truncated}}}, rows.Err()
}
