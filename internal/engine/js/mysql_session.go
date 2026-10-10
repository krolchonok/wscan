package js

import (
	"context"
	"database/sql"
	"fmt"
	mysql "github.com/go-sql-driver/mysql"
	"strings"
	"time"
)

type MySQLSessionOptions struct {
	Host                                  string
	Port                                  int
	Username, Password, Database, SSLMode string
	Timeout                               time.Duration
}
type MySQLSession struct{ db *sql.DB }

func OpenMySQLSession(ctx context.Context, o MySQLSessionOptions) (*MySQLSession, error) {
	cfg := mysql.NewConfig()
	cfg.User = o.Username
	cfg.Passwd = o.Password
	cfg.Net = "tcp"
	cfg.Addr = joinAddr(o.Host, o.Port)
	cfg.DBName = o.Database
	cfg.Timeout = o.Timeout
	cfg.ReadTimeout = o.Timeout
	cfg.WriteTimeout = o.Timeout
	cfg.ParseTime = true
	cfg.TLSConfig = o.SSLMode
	if cfg.TLSConfig == "" {
		cfg.TLSConfig = "true"
	}
	// MultiStatements and local file access remain disabled.
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &MySQLSession{db: db}, nil
}
func (s *MySQLSession) Close() { s.db.Close() }

// Reject file output and executable comments outside quoted SQL literals.
func validateMySQLRead(query string) error {
	fields := strings.Fields(query)
	if len(fields) == 0 {
		return fmt.Errorf("пустой запрос")
	}
	switch strings.ToUpper(fields[0]) {
	case "SELECT", "WITH", "EXPLAIN", "SHOW", "DESCRIBE", "DESC":
	default:
		return fmt.Errorf("доступны SELECT, WITH, EXPLAIN, SHOW и DESCRIBE")
	}
	var token strings.Builder
	check := func() error {
		word := strings.ToUpper(token.String())
		token.Reset()
		if word == "INTO" {
			return fmt.Errorf("SELECT INTO запрещён в режиме чтения")
		}
		return nil
	}
	for i := 0; i < len(query); {
		c := query[i]
		if c == '\'' || c == '"' || c == '`' {
			if err := check(); err != nil {
				return err
			}
			quote := c
			i++
			closed := false
			for i < len(query) {
				if query[i] == '\\' {
					return fmt.Errorf("используй удвоенные кавычки вместо обратного слеша")
				}
				if query[i] == quote {
					if i+1 < len(query) && query[i+1] == quote {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return fmt.Errorf("незакрытая кавычка")
			}
			continue
		}
		if c == '#' || (c == '-' && i+2 < len(query) && query[i+1] == '-' && query[i+2] <= ' ') {
			if err := check(); err != nil {
				return err
			}
			for i < len(query) && query[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(query) && query[i+1] == '*' {
			if err := check(); err != nil {
				return err
			}
			if i+2 < len(query) && (query[i+2] == '!' || (query[i+2] == 'M' && i+3 < len(query) && query[i+3] == '!')) {
				return fmt.Errorf("исполняемые SQL-комментарии запрещены")
			}
			end := strings.Index(query[i+2:], "*/")
			if end < 0 {
				return fmt.Errorf("незакрытый комментарий")
			}
			i += end + 4
			continue
		}
		if c == ';' {
			return fmt.Errorf("введи один запрос без точки с запятой")
		}
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c >= '0' && c <= '9' {
			token.WriteByte(c)
		} else {
			if err := check(); err != nil {
				return err
			}
		}
		i++
	}
	return check()
}

// Read executes one query inside a read-only transaction and always rolls it back.
func (s *MySQLSession) Read(ctx context.Context, query string) (map[string]any, error) {
	if err := validateMySQLRead(query); err != nil {
		return nil, err
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
