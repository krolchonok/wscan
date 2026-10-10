package js

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"time"

	"github.com/dop251/goja"
	_ "github.com/lib/pq"
)

// postgresModule exposes PGClient as a goja constructor — see smbModule's
// doc comment for why a plain FunctionCall-shaped factory isn't enough
// (real templates use both `new postgres.PGClient;` and `postgres.PGClient()`).
func postgresModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	obj := vm.NewObject()
	ctor := func(call goja.ConstructorCall) *goja.Object {
		return vm.ToValue(&PGClient{ctx: ctx, timeout: timeout}).(*goja.Object)
	}
	_ = obj.Set("PGClient", ctor)
	return obj
}

// PGClient mirrors nuclei/postgres.PGClient.
type PGClient struct {
	ctx     context.Context
	timeout time.Duration
}

// NewPGClient constructs a PGClient for direct use outside the goja runtime
// — see ssh.go's NewSSHClient.
func NewPGClient(ctx context.Context, timeout time.Duration) *PGClient {
	return &PGClient{ctx: ctx, timeout: timeout}
}

func (c *PGClient) IsPostgres(host string, port int) (bool, error) {
	return dialOpen(c.ctx, "tcp", host, fmt.Sprint(port), c.timeout), nil
}

func (c *PGClient) Connect(host string, port int, user, pass string) (bool, error) {
	db, err := c.open(host, port, user, pass, "postgres")
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

func (c *PGClient) ExecuteQuery(host string, port int, user, pass, dbName, query string) (map[string]any, error) {
	if dbName == "" {
		dbName = "postgres"
	}
	db, err := c.open(host, port, user, pass, dbName)
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

func (c *PGClient) open(host string, port int, user, pass, dbname string) (*sql.DB, error) {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, pass),
		Host:   joinAddr(host, port),
		Path:   "/" + dbname,
	}
	q := u.Query()
	q.Set("sslmode", "disable")
	q.Set("connect_timeout", fmt.Sprintf("%d", int(c.timeout.Seconds())))
	u.RawQuery = q.Encode()
	return sql.Open("postgres", u.String())
}
