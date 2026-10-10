package js

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
	mssql "github.com/microsoft/go-mssqldb"
	_ "github.com/microsoft/go-mssqldb/integratedauth/ntlm"
)

func mssqlModule(vm *goja.Runtime, ctx context.Context, timeout time.Duration) goja.Value {
	obj := vm.NewObject()
	_ = obj.Set("MSSQLClient", func(call goja.ConstructorCall) *goja.Object {
		client := NewMSSQLClient(ctx, timeout)
		if h, p := vm.Get("Host"), vm.Get("Port"); h != nil && p != nil && !goja.IsUndefined(h) && !goja.IsUndefined(p) {
			host, port, err := asHostPort(h.Export(), p.Export())
			if err == nil {
				client.selectedHost, client.selectedPort = host, port
			}
		}
		return vm.ToValue(client).(*goja.Object)
	})
	return obj
}

type MSSQLClient struct {
	selectedHost string
	selectedPort int
	ctx          context.Context
	timeout      time.Duration
}

func NewMSSQLClient(ctx context.Context, timeout time.Duration) *MSSQLClient {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &MSSQLClient{ctx: ctx, timeout: timeout}
}

// MSSQLOptions binds a session to one explicitly selected TCP endpoint.
// Domain selects Windows NTLM authentication; an empty Domain uses SQL login.
type MSSQLOptions struct {
	Host                                 string
	Port                                 int
	Username, Password, Domain, Database string
	Encrypt, TrustServerCertificate      bool
	Timeout                              time.Duration
}

type MSSQLSession struct {
	db      *sql.DB
	conn    *sql.Conn
	timeout time.Duration
}

func OpenMSSQL(ctx context.Context, o MSSQLOptions) (*MSSQLSession, error) {
	if o.Host == "" || o.Port < 1 || o.Port > 65535 {
		return nil, fmt.Errorf("MSSQL: требуется хост и выбранный TCP-порт")
	}
	if o.Username == "" {
		return nil, fmt.Errorf("MSSQL: нужно имя SQL/Windows-учётки; анонимный вход не поддерживается")
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	user := o.Username
	if o.Domain != "" {
		user = o.Domain + `\` + user
	}
	u := &url.URL{Scheme: "sqlserver", Host: net.JoinHostPort(o.Host, strconv.Itoa(o.Port)), User: url.UserPassword(user, o.Password)}
	q := url.Values{"protocol": {"tcp"}, "connection timeout": {strconv.Itoa(max(1, int(o.Timeout.Seconds())))}, "encrypt": {strconv.FormatBool(o.Encrypt)}, "TrustServerCertificate": {strconv.FormatBool(o.TrustServerCertificate)}, "app name": {"wscan"}, "disableRetry": {"true"}}
	if o.Domain != "" || strings.Contains(o.Username, `\`) {
		q.Set("authenticator", "ntlm")
	}
	if o.Database != "" {
		q.Set("database", o.Database)
	}
	u.RawQuery = q.Encode()
	connector, err := mssql.NewConnector(u.String())
	if err != nil {
		return nil, err
	}
	connector.Dialer = mssqlEndpointDialer{host: o.Host, port: o.Port, timeout: o.Timeout}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	loginCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	if err = db.PingContext(loginCtx); err != nil {
		db.Close()
		return nil, err
	}
	conn, err := db.Conn(loginCtx)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &MSSQLSession{db: db, conn: conn, timeout: o.Timeout}, nil
}
func (s *MSSQLSession) Close() error { _ = s.conn.Close(); return s.db.Close() }

// Query preserves a connection (USE/session context), with bounded display output.
// Arbitrary SQL is deliberately gated by its caller, not classified by SQL text.
func (s *MSSQLSession) Query(ctx context.Context, query string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	rows, err := s.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sets := []map[string]any{}
	budget := 1024 * 1024
	for {
		cols, err := rows.Columns()
		if err != nil {
			return nil, err
		}
		values := [][]any{}
		truncated := false
		for rows.Next() {
			if len(values) >= 500 || budget <= 0 {
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
				if str, ok := vals[i].(string); ok {
					limit := min(8192, max(0, budget))
					if len(str) > limit {
						vals[i] = str[:limit]
						truncated = true
					}
					budget -= len(fmt.Sprint(vals[i]))
				} else {
					budget -= 32
				}
			}
			values = append(values, vals)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		sets = append(sets, map[string]any{"Columns": cols, "Rows": values, "Count": len(values), "Truncated": truncated})
		if truncated || len(sets) >= 8 || !rows.NextResultSet() {
			break
		}
	}
	// Keep Nuclei's historical row-map shape as well as ordered result sets.
	first := sets[0]
	mapped := []map[string]any{}
	cols := first["Columns"].([]string)
	for _, vals := range first["Rows"].([][]any) {
		row := map[string]any{}
		for i, col := range cols {
			row[col] = vals[i]
		}
		mapped = append(mapped, row)
	}
	return map[string]any{"Rows": mapped, "Count": len(mapped), "ResultSets": sets, "Truncated": first["Truncated"]}, nil
}

func (c *MSSQLClient) Connect(host string, port int, user, pass string) (bool, error) {
	return c.ConnectWithDomain(host, port, "", user, pass)
}
func (c *MSSQLClient) ConnectWithDomain(host string, port int, domain, user, pass string) (bool, error) {
	if err := c.checkEndpoint(host, port); err != nil {
		return false, err
	}
	s, err := OpenMSSQL(c.ctx, MSSQLOptions{Host: host, Port: port, Username: user, Password: pass, Domain: domain, Timeout: c.timeout})
	if err != nil {
		return false, err
	}
	defer s.Close()
	return true, nil
}
func (c *MSSQLClient) ExecuteQuery(host string, port int, user, pass, query string) (map[string]any, error) {
	if err := c.checkEndpoint(host, port); err != nil {
		return nil, err
	}
	s, err := OpenMSSQL(c.ctx, MSSQLOptions{Host: host, Port: port, Username: user, Password: pass, Timeout: c.timeout})
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.Query(c.ctx, query)
}

// IsMssql validates a TDS PRELOGIN response, rather than accepting any open TCP port.
func (c *MSSQLClient) IsMssql(host string, port int) (bool, error) {
	_, err := c.CollectMetadata(host, port)
	return err == nil, err
}
func (c *MSSQLClient) CollectMetadata(host string, port int) (map[string]any, error) {
	if err := c.checkEndpoint(host, port); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "tcp", joinAddr(host, port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(c.timeout))
	// VERSION (6 bytes), ENCRYPTION (1 byte), terminator; offsets are relative to payload.
	packet := []byte{0x12, 0x01, 0x00, 0x1a, 0, 0, 1, 0, 0, 0, 11, 0, 6, 1, 0, 17, 0, 1, 0xff, 0, 0, 0, 0, 0, 0, 0}
	if _, err = conn.Write(packet); err != nil {
		return nil, err
	}
	payload := []byte{}
	for len(payload) < 65536 {
		header := make([]byte, 8)
		if _, err = io.ReadFull(conn, header); err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint16(header[2:4]))
		if header[0] != 4 || size < 9 || size > 32768 {
			return nil, fmt.Errorf("ответ не является TDS PRELOGIN")
		}
		part := make([]byte, size-8)
		if _, err = io.ReadFull(conn, part); err != nil {
			return nil, err
		}
		payload = append(payload, part...)
		if header[1]&1 != 0 {
			break
		}
	}
	meta := map[string]any{"Port": port, "Protocol": "tds", "Version": ""}
	found := false
	for at := 0; at < len(payload); at += 5 {
		token := payload[at]
		if token == 255 {
			if !found {
				return nil, fmt.Errorf("TDS: нет версии в PRELOGIN")
			}
			return meta, nil
		}
		if at+5 > len(payload) {
			break
		}
		off := int(binary.BigEndian.Uint16(payload[at+1 : at+3]))
		n := int(binary.BigEndian.Uint16(payload[at+3 : at+5]))
		if off < at+5 || off+n > len(payload) {
			break
		}
		if token == 0 && n == 6 {
			b := payload[off : off+n]
			meta["Version"] = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], binary.BigEndian.Uint16(b[2:4]), binary.BigEndian.Uint16(b[4:6]))
			found = true
		}
		if token == 1 && n == 1 {
			meta["Encryption"] = int(payload[off])
		}
	}
	return nil, fmt.Errorf("некорректный TDS PRELOGIN")
}

var MSSQLAuditQueries = map[string]string{
	"identity":       `SELECT @@VERSION AS version, SERVERPROPERTY('ProductVersion') AS product_version, SERVERPROPERTY('Edition') AS edition, ORIGINAL_LOGIN() AS original_login, SUSER_SNAME() AS current_login, USER_NAME() AS database_user, DB_NAME() AS current_database, IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin`,
	"permissions":    `SELECT * FROM fn_my_permissions(NULL, 'SERVER'); SELECT * FROM fn_my_permissions(NULL, 'DATABASE')`,
	"databases":      `SELECT name, state_desc, is_trustworthy_on, SUSER_SNAME(owner_sid) AS owner_name FROM sys.databases`,
	"tables":         `SELECT TOP (500) TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES ORDER BY TABLE_SCHEMA, TABLE_NAME`,
	"columns":        `SELECT TOP (500) TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION`,
	"configuration":  `SELECT name, value AS configured_value, value_in_use AS active_value FROM sys.configurations WHERE name IN ('xp_cmdshell','clr enabled','Ole Automation Procedures','Ad Hoc Distributed Queries','cross db ownership chaining')`,
	"impersonate":    `SELECT grantee.name AS grantee, target.name AS target_login, p.state_desc FROM sys.server_permissions p JOIN sys.server_principals grantee ON grantee.principal_id=p.grantee_principal_id LEFT JOIN sys.server_principals target ON target.principal_id=p.major_id WHERE p.permission_name='IMPERSONATE'; SELECT grantee.name AS grantee, target.name AS target_user, p.state_desc FROM sys.database_permissions p JOIN sys.database_principals grantee ON grantee.principal_id=p.grantee_principal_id LEFT JOIN sys.database_principals target ON target.principal_id=p.major_id WHERE p.permission_name='IMPERSONATE'`,
	"linked-servers": `SELECT name, product, provider, data_source, is_linked, is_rpc_out_enabled FROM sys.servers WHERE is_linked=1`,
}

func (s *MSSQLSession) Audit(ctx context.Context, module string) (map[string]any, error) {
	q, ok := MSSQLAuditQueries[strings.TrimSpace(module)]
	if !ok {
		return nil, fmt.Errorf("неизвестный модуль MSSQL")
	}
	return s.Query(ctx, q)
}

// A server routing token must never redirect authentication to a neighbouring
// instance/host. HostDialer also preserves the requested DNS identity for TLS.
type mssqlEndpointDialer struct {
	host    string
	port    int
	timeout time.Duration
}

func (d mssqlEndpointDialer) HostName() string { return d.host }
func (d mssqlEndpointDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if network != "tcp" || !strings.EqualFold(host, d.host) || port != strconv.Itoa(d.port) {
		return nil, fmt.Errorf("MSSQL: переход на другой сервис запрещён")
	}
	return (&net.Dialer{Timeout: d.timeout}).DialContext(ctx, "tcp", net.JoinHostPort(d.host, port))
}

func (c *MSSQLClient) checkEndpoint(host string, port int) error {
	if c.selectedHost != "" && (!strings.EqualFold(strings.Trim(host, "[]"), strings.Trim(c.selectedHost, "[]")) || port != c.selectedPort) {
		return fmt.Errorf("MSSQL: запрос вне выбранного сервиса")
	}
	return nil
}
