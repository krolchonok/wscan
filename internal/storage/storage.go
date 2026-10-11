package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	_ "modernc.org/sqlite"
	"wscan/internal/domain"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS inventory_resets(project_id INTEGER NOT NULL,host TEXT NOT NULL,through_run INTEGER NOT NULL,aliases TEXT NOT NULL,PRIMARY KEY(project_id,host))`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS inventory_exclusions(project_id INTEGER NOT NULL,host TEXT NOT NULL,service_key TEXT NOT NULL,PRIMARY KEY(project_id,host,service_key))`); err != nil {
		db.Close()
		return nil, err
	}
	// credentials/credential_attempts back post-auth login checks (see
	// internal/storage/credentials.go). credential_attempts is deliberately
	// project_id+username scoped, not per-host/per-protocol: an AD account's
	// lockout counter is shared across every service authenticating against
	// the same domain controller, so a lockout-safety check must see every
	// attempt against that username, not just the ones on the current target
	// or protocol.
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS credentials(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, type TEXT NOT NULL, username TEXT NOT NULL, domain TEXT NOT NULL DEFAULT '', secret TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '')`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS credential_attempts(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, target TEXT NOT NULL, username TEXT NOT NULL, protocol TEXT NOT NULL, success INTEGER NOT NULL, attempted_at TEXT NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_credential_attempts_lookup ON credential_attempts(project_id, username, attempted_at)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err = db.Exec(`PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, rps INTEGER NOT NULL DEFAULT 5, concurrency INTEGER NOT NULL DEFAULT 4, timeout_seconds INTEGER NOT NULL DEFAULT 10, retries INTEGER NOT NULL DEFAULT 0, discovery_enabled INTEGER NOT NULL DEFAULT 1, all_ports INTEGER NOT NULL DEFAULT 1, discovery_rps INTEGER NOT NULL DEFAULT 1000, discovery_concurrency INTEGER NOT NULL DEFAULT 256, allow_code_exec INTEGER NOT NULL DEFAULT 0, allow_exploit INTEGER NOT NULL DEFAULT 0, allow_credential_attack INTEGER NOT NULL DEFAULT 0, lockout_max_attempts INTEGER NOT NULL DEFAULT 0, lockout_window_minutes INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS targets(project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, url TEXT NOT NULL, PRIMARY KEY(project_id,url)); CREATE TABLE IF NOT EXISTS project_templates(project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, template_id TEXT NOT NULL, PRIMARY KEY(project_id,template_id)); CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id), started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL); CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE, data TEXT NOT NULL); CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE, data TEXT NOT NULL);`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS host_names(project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,host TEXT NOT NULL,names TEXT NOT NULL,queried_at TEXT NOT NULL,PRIMARY KEY(project_id,host))`); err != nil {
		db.Close()
		return nil, err
	}
	var dnsSourceColumns int
	if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info('host_names') WHERE name='dns_server'`).Scan(&dnsSourceColumns); err != nil {
		db.Close()
		return nil, err
	}
	if dnsSourceColumns == 0 {
		if _, err = db.Exec(`ALTER TABLE host_names ADD COLUMN dns_server TEXT NOT NULL DEFAULT ''`); err != nil {
			db.Close()
			return nil, err
		}
	}
	// Older databases stored a profile that could override the selected checks.
	// Remove it while preserving projects, runs and their results.
	for _, table := range []string{"projects", "runs"} {
		var count int
		if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name='profile'`, table).Scan(&count); err != nil {
			db.Close()
			return nil, err
		}
		if count > 0 {
			if _, err = db.Exec("ALTER TABLE " + table + " DROP COLUMN profile"); err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	// Databases created before code: support won't have this column — the
	// CREATE TABLE above only applies to a brand new database.
	var allowCodeExecCol int
	if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info('projects') WHERE name='allow_code_exec'`).Scan(&allowCodeExecCol); err != nil {
		db.Close()
		return nil, err
	}
	if allowCodeExecCol == 0 {
		if _, err = db.Exec(`ALTER TABLE projects ADD COLUMN allow_code_exec INTEGER NOT NULL DEFAULT 0`); err != nil {
			db.Close()
			return nil, err
		}
	}
	// Databases created before exploit: support won't have this column either.
	var allowExploitCol int
	if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info('projects') WHERE name='allow_exploit'`).Scan(&allowExploitCol); err != nil {
		db.Close()
		return nil, err
	}
	if allowExploitCol == 0 {
		if _, err = db.Exec(`ALTER TABLE projects ADD COLUMN allow_exploit INTEGER NOT NULL DEFAULT 0`); err != nil {
			db.Close()
			return nil, err
		}
	}
	// Databases created before credential-spray support won't have these
	// columns either — see domain.Project.AllowCredentialAttack/
	// LockoutMaxAttempts/LockoutWindowMinutes.
	for _, col := range []struct{ name, ddl string }{
		{"allow_credential_attack", "ALTER TABLE projects ADD COLUMN allow_credential_attack INTEGER NOT NULL DEFAULT 0"},
		{"lockout_max_attempts", "ALTER TABLE projects ADD COLUMN lockout_max_attempts INTEGER NOT NULL DEFAULT 0"},
		{"lockout_window_minutes", "ALTER TABLE projects ADD COLUMN lockout_window_minutes INTEGER NOT NULL DEFAULT 0"},
	} {
		var n int
		if err = db.QueryRow(`SELECT count(*) FROM pragma_table_info('projects') WHERE name=?`, col.name).Scan(&n); err != nil {
			db.Close()
			return nil, err
		}
		if n == 0 {
			if _, err = db.Exec(col.ddl); err != nil {
				db.Close()
				return nil, err
			}
		}
	}
	// Watermarks above any known run id (history purge / id reuse) would hide
	// every future scan forever — drop them so the desk can show results again.
	if _, err = db.Exec(`DELETE FROM inventory_resets WHERE through_run > (SELECT coalesce(max(id),0) FROM runs WHERE runs.project_id = inventory_resets.project_id)`); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) CreateProject(ctx context.Context, name string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO projects(name,all_ports) VALUES(?,1)`, name)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// CreateProjectWithTargets creates a project and its initial scope atomically.
func (s *Store) CreateProjectWithTargets(ctx context.Context, name string, targets []string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO projects(name,all_ports) VALUES(?,0)`, name)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, target := range targets {
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO targets(project_id,url) VALUES(?,?)`, id, target); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}
func (s *Store) ListProjects(ctx context.Context) ([]domain.Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,rps,concurrency,timeout_seconds,retries,discovery_enabled,all_ports,discovery_rps,discovery_concurrency,allow_code_exec,allow_exploit,allow_credential_attack,lockout_max_attempts,lockout_window_minutes FROM projects ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ps []domain.Project
	for rows.Next() {
		var p domain.Project
		if err = rows.Scan(&p.ID, &p.Name, &p.RPS, &p.Concurrency, &p.TimeoutSeconds, &p.Retries, &p.DiscoveryEnabled, &p.AllPorts, &p.DiscoveryRPS, &p.DiscoveryConcurrency, &p.AllowCodeExec, &p.AllowExploit, &p.AllowCredentialAttack, &p.LockoutMaxAttempts, &p.LockoutWindowMinutes); err != nil {
			return nil, err
		}
		ps = append(ps, p)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for i := range ps {
		ps[i].Targets, err = s.targets(ctx, ps[i].ID)
		if err != nil {
			return nil, err
		}
		ps[i].TemplateIDs, err = s.templateIDs(ctx, ps[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return ps, nil
}
func (s *Store) AddTarget(ctx context.Context, id int64, target string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO targets(project_id,url) VALUES(?,?)`, id, target)
	return err
}
func (s *Store) RemoveTarget(ctx context.Context, id int64, target string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM targets WHERE project_id=? AND url=?`, id, target)
	return err
}
func (s *Store) ReplaceTarget(ctx context.Context, id int64, oldTarget, newTarget string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM targets WHERE project_id=? AND url=?`, id, oldTarget); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO targets(project_id,url) VALUES(?,?)`, id, newTarget); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) ToggleTemplate(ctx context.Context, id int64, template string) error {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM project_templates WHERE project_id=? AND template_id=?`, id, template).Scan(&n)
	if n > 0 {
		_, err := s.db.ExecContext(ctx, `DELETE FROM project_templates WHERE project_id=? AND template_id=?`, id, template)
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO project_templates(project_id,template_id) VALUES(?,?)`, id, template)
	return err
}

// SetTemplates selects or clears a group of template IDs in one transaction.
func (s *Store) SetTemplates(ctx context.Context, id int64, templates []string, selected bool) error {
	if len(templates) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := `INSERT OR IGNORE INTO project_templates(project_id,template_id) VALUES(?,?)`
	if !selected {
		query = `DELETE FROM project_templates WHERE project_id=? AND template_id=?`
	}
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, template := range templates {
		if _, err = stmt.ExecContext(ctx, id, template); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) SetLimits(ctx context.Context, id int64, rps, concurrency int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE projects SET rps=?,concurrency=? WHERE id=?`, rps, concurrency, id)
	return err
}
func (s *Store) SetProjectScanSettings(ctx context.Context, p domain.Project) error {
	_, err := s.db.ExecContext(ctx, `UPDATE projects SET rps=?,concurrency=?,timeout_seconds=?,retries=?,all_ports=?,discovery_enabled=?,discovery_rps=?,discovery_concurrency=?,allow_code_exec=?,allow_exploit=?,allow_credential_attack=?,lockout_max_attempts=?,lockout_window_minutes=? WHERE id=?`, p.RPS, p.Concurrency, p.TimeoutSeconds, p.Retries, p.AllPorts, p.DiscoveryEnabled, p.DiscoveryRPS, p.DiscoveryConcurrency, p.AllowCodeExec, p.AllowExploit, p.AllowCredentialAttack, p.LockoutMaxAttempts, p.LockoutWindowMinutes, p.ID)
	return err
}
func (s *Store) SetScanSettings(ctx context.Context, id int64, timeoutSeconds, retries int, allPorts, discoveryEnabled bool, discoveryRPS, discoveryConcurrency int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE projects SET timeout_seconds=?,retries=?,all_ports=?,discovery_enabled=?,discovery_rps=?,discovery_concurrency=? WHERE id=?`, timeoutSeconds, retries, allPorts, discoveryEnabled, discoveryRPS, discoveryConcurrency, id)
	return err
}
func (s *Store) StartRun(ctx context.Context, projectID int64) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `INSERT INTO runs(project_id,started_at,status) VALUES(?,?,'running')`, projectID, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}
func (s *Store) SaveFinding(ctx context.Context, runID int64, f domain.Finding) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO findings(run_id,data) VALUES(?,?)`, runID, string(b))
	return err
}
func (s *Store) SaveService(ctx context.Context, runID int64, service domain.Service) error {
	b, err := json.Marshal(service)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO services(run_id,data) VALUES(?,?)`, runID, string(b))
	return err
}
func (s *Store) FinishRun(ctx context.Context, id int64, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET status=?,finished_at=? WHERE id=?`, status, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}
func (s *Store) Findings(ctx context.Context, runID int64) ([]domain.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM findings WHERE run_id=? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Finding
	for rows.Next() {
		var b string
		var f domain.Finding
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(b), &f); err != nil {
			return nil, err
		}
		f.Severity = domain.EffectiveSeverity(f)
		out = append(out, f)
	}
	return out, rows.Err()
}
func (s *Store) Runs(ctx context.Context, projectID int64) ([]domain.Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,project_id,started_at,coalesce(finished_at,''),status FROM runs WHERE project_id=? ORDER BY id DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Run
	for rows.Next() {
		var r domain.Run
		var start, finish string
		if err = rows.Scan(&r.ID, &r.ProjectID, &start, &finish, &r.Status); err != nil {
			return nil, err
		}
		r.StartedAt, _ = time.Parse(time.RFC3339Nano, start)
		if finish != "" {
			r.FinishedAt, _ = time.Parse(time.RFC3339Nano, finish)
		}
		out = append(out, r)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Findings, err = s.Findings(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Services, err = s.Services(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (s *Store) Services(ctx context.Context, runID int64) ([]domain.Service, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM services WHERE run_id=? ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Service
	for rows.Next() {
		var raw string
		var service domain.Service
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &service); err != nil {
			return nil, err
		}
		out = append(out, service)
	}
	return out, rows.Err()
}
func (s *Store) targets(ctx context.Context, id int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT url FROM targets WHERE project_id=? ORDER BY url`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err = rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) templateIDs(ctx context.Context, id int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT template_id FROM project_templates WHERE project_id=? ORDER BY template_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err = rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
