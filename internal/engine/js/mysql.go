package js

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/dop251/goja"
	mysql "github.com/go-sql-driver/mysql"
)

// mysqlModule exposes MySQLClient as a goja constructor so both
// `new m.MySQLClient()` and `m.MySQLClient()` work — see smbModule's doc
// comment for why a plain FunctionCall-shaped factory isn't enough.
func mysqlModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	obj := vm.NewObject()
	ctor := func(call goja.ConstructorCall) *goja.Object {
		return vm.ToValue(&MySQLClient{ctx: ctx, timeout: timeout}).(*goja.Object)
	}
	_ = obj.Set("MySQLClient", ctor)
	return obj
}

// MySQLClient mirrors nuclei/mysql.MySQLClient.
type MySQLClient struct {
	ctx     context.Context
	timeout time.Duration
}

// NewMySQLClient constructs a MySQLClient for direct use outside the goja
// runtime — see ssh.go's NewSSHClient.
func NewMySQLClient(ctx context.Context, timeout time.Duration) *MySQLClient {
	return &MySQLClient{ctx: ctx, timeout: timeout}
}

func (c *MySQLClient) Connect(host string, port int, user, pass string) (bool, error) {
	db, err := c.open(host, port, user, pass, "")
	if err != nil {
		return false, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (c *MySQLClient) ExecuteQuery(host string, port int, user, pass, query string) (map[string]any, error) {
	db, err := c.open(host, port, user, pass, "")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return sqlResult(rows)
}

func (c *MySQLClient) IsMySQL(host string, port int) (bool, error) {
	d := netDialOK(c.ctx, host, port, c.timeout)
	return d, nil
}

func (c *MySQLClient) open(host string, port int, user, pass, dbname string) (*sql.DB, error) {
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr = user, pass, "tcp", joinAddr(host, port)
	cfg.DBName = dbname
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = c.timeout, c.timeout, c.timeout
	cfg.ParseTime = true
	return sql.Open("mysql", cfg.FormatDSN())
}

func netDialOK(ctx context.Context, host string, port int, timeout time.Duration) bool {
	return dialOpen(ctx, "tcp", host, fmt.Sprint(port), timeout)
}

func sqlResult(rows *sql.Rows) (map[string]any, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var outRows []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := map[string]any{}
		for i, col := range cols {
			switch v := vals[i].(type) {
			case []byte:
				row[col] = string(v)
			default:
				row[col] = v
			}
		}
		outRows = append(outRows, row)
	}
	if outRows == nil {
		outRows = []map[string]any{}
	}
	return map[string]any{"Rows": outRows, "Count": len(outRows)}, rows.Err()
}
