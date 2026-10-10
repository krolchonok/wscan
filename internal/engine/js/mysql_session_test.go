package js

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"testing"
)

func TestMySQLReadValidation(t *testing.T) {
	for _, q := range []string{"SELECT * FROM users", "SHOW DATABASES", "DESCRIBE users", "WITH a AS (SELECT 1) SELECT * FROM a", "SELECT 'INTO OUTFILE; /*! */'", "SELECT `into` FROM users", "SELECT 1 /* normal comment */", "SELECT 'a''b'"} {
		if err := validateMySQLRead(q); err != nil {
			t.Fatalf("rejected %s: %v", q, err)
		}
	}
	for _, q := range []string{"DELETE FROM users", "SET transaction_read_only=off", "SELECT 1; DELETE FROM users", "SELECT * FROM users INTO OUTFILE '/tmp/a'", "SELECT 1 INTO/**/DUMPFILE '/tmp/a'", "SELECT 1 /*! INTO OUTFILE '/tmp/a' */", "SELECT 1 /*M! INTO OUTFILE '/tmp/a' */", "SELECT 'unclosed", "SELECT 'a\\'", ""} {
		if err := validateMySQLRead(q); err == nil {
			t.Fatalf("accepted %s", q)
		}
	}
}

type mysqlReadTestConn struct {
	readOnly, rolledBack bool
	fail                 bool
}

func (c *mysqlReadTestConn) Prepare(string) (driver.Stmt, error) {
	if c.fail {
		return nil, fmt.Errorf("prepare failed")
	}
	return mysqlReadTestStmt{}, nil
}
func (c *mysqlReadTestConn) Close() error              { return nil }
func (c *mysqlReadTestConn) Begin() (driver.Tx, error) { return nil, fmt.Errorf("expected BeginTx") }
func (c *mysqlReadTestConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	c.readOnly = o.ReadOnly
	return mysqlReadTestTx{c}, nil
}

type mysqlReadTestTx struct{ c *mysqlReadTestConn }

func (t mysqlReadTestTx) Commit() error   { return fmt.Errorf("unexpected commit") }
func (t mysqlReadTestTx) Rollback() error { t.c.rolledBack = true; return nil }

type mysqlReadTestStmt struct{}

func (mysqlReadTestStmt) Close() error  { return nil }
func (mysqlReadTestStmt) NumInput() int { return 0 }
func (mysqlReadTestStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, fmt.Errorf("unexpected exec")
}
func (mysqlReadTestStmt) Query([]driver.Value) (driver.Rows, error) { return &mysqlReadTestRows{}, nil }

type mysqlReadTestRows struct{ n int }

func (*mysqlReadTestRows) Columns() []string { return []string{"value"} }
func (*mysqlReadTestRows) Close() error      { return nil }
func (r *mysqlReadTestRows) Next(v []driver.Value) error {
	if r.n >= 501 {
		return io.EOF
	}
	v[0] = []byte("data")
	r.n++
	return nil
}

type mysqlReadTestConnector struct{ c *mysqlReadTestConn }

func (c mysqlReadTestConnector) Connect(context.Context) (driver.Conn, error) { return c.c, nil }
func (mysqlReadTestConnector) Driver() driver.Driver                          { return mysqlReadTestDriver{} }

type mysqlReadTestDriver struct{}

func (mysqlReadTestDriver) Open(string) (driver.Conn, error) { return nil, fmt.Errorf("use connector") }
func TestMySQLReadTransactionAndRowLimit(t *testing.T) {
	for _, fail := range []bool{false, true} {
		c := &mysqlReadTestConn{fail: fail}
		db := sql.OpenDB(mysqlReadTestConnector{c})
		s := &MySQLSession{db: db}
		result, err := s.Read(context.Background(), "SELECT value FROM users")
		s.Close()
		if !c.readOnly || !c.rolledBack {
			t.Fatal("missing read-only transaction or rollback")
		}
		if fail {
			if err == nil {
				t.Fatal("prepare error lost")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		set := result["ResultSets"].([]map[string]any)[0]
		if set["Count"] != 500 || set["Truncated"] != true || set["Rows"].([][]any)[0][0] != "data" {
			t.Fatalf("incorrect result %v", set["Count"])
		}
	}
}
