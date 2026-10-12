package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"wscan/internal/adscan"
	"wscan/internal/engine"
)

type Outcome struct {
	Result      engine.Result
	AD          *adscan.Result
	ProjectID   int64
	ProjectName string
}
type Executor func(context.Context, Reporter) (Outcome, error)
type JobRequest struct {
	Fingerprint string   `json:"fingerprint,omitempty"`
	ProjectID   int64    `json:"project_id"`
	Kind        string   `json:"kind"`
	Label       string   `json:"label"`
	Targets     []string `json:"targets"`
	Scope       string   `json:"scope"`
	Checks      []string `json:"checks,omitempty"`
	Options     []string `json:"options,omitempty"`
	Source      string   `json:"source"`
}
type JobEvent struct {
	Sequence uint64    `json:"sequence"`
	Time     time.Time `json:"time"`
	Message  string    `json:"message"`
}
type Job struct {
	Key      string `json:"idempotency_key,omitempty"`
	ID       int    `json:"id"`
	Revision uint64 `json:"revision"`
	JobRequest
	Status           string     `json:"status"`
	Stage            string     `json:"stage"`
	Completed        int        `json:"completed"`
	Total            int        `json:"total"`
	RunID            int64      `json:"run_id"`
	Findings         int        `json:"findings"`
	Error            string     `json:"error,omitempty"`
	PersistenceError string     `json:"persistence_error,omitempty"`
	Started          time.Time  `json:"started"`
	Ended            time.Time  `json:"ended,omitempty"`
	Journal          []JobEvent `json:"journal"`
	Outcome          *Outcome   `json:"-"`
}
type jobState struct {
	job       Job
	cancel    context.CancelFunc
	lastSaved time.Time
}
type JobStore interface {
	SaveJob(context.Context, int, []byte) error
	LoadJobs(context.Context) ([][]byte, error)
}
type Manager struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	store    JobStore
	jobs     map[int]*jobState
	keys     map[string]int
	next     int
	revision uint64
	closing  bool
	wg       sync.WaitGroup
}

func NewManager(parent context.Context, store JobStore) (*Manager, error) {
	ctx, cancel := context.WithCancel(parent)
	m := &Manager{ctx: ctx, cancel: cancel, store: store, jobs: map[int]*jobState{}, keys: map[string]int{}}
	if store != nil {
		records, err := store.LoadJobs(ctx)
		if err != nil {
			cancel()
			return nil, err
		}
		for _, raw := range records {
			var j Job
			if err := json.Unmarshal(raw, &j); err != nil {
				cancel()
				return nil, fmt.Errorf("job history: %w", err)
			}
			m.next = max(m.next, j.ID)
			if j.Status == "running" || j.Status == "cancelling" {
				j.Status = "interrupted"
				j.Stage = "Прервано завершением программы"
				j.Ended = time.Now()
				j.Journal = append(j.Journal, JobEvent{Time: time.Now(), Message: j.Stage})
			}
			m.revision++
			j.Revision = m.revision
			state := &jobState{job: j}
			m.jobs[j.ID] = state
			if j.Key != "" {
				m.keys[j.Key] = j.ID
			}
			if err := m.saveLocked(state); err != nil {
				cancel()
				return nil, err
			}
		}
	}
	return m, nil
}
func (m *Manager) Start(req JobRequest, key string, execute Executor) (Job, error) {
	if execute == nil {
		return Job{}, fmt.Errorf("исполнитель не задан")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing || m.ctx.Err() != nil {
		return Job{}, fmt.Errorf("программа завершает работу")
	}
	if key != "" {
		if id, ok := m.keys[key]; ok {
			old := m.jobs[id]
			a, _ := json.Marshal(old.job.JobRequest)
			b, _ := json.Marshal(req)
			same := string(a) == string(b)
			if req.Fingerprint != "" {
				same = old.job.Fingerprint == req.Fingerprint
			}
			if !same {
				return Job{}, fmt.Errorf("ключ запуска уже использован с другими параметрами")
			}
			return cloneJob(old.job), nil
		}
	}
	m.next++
	ctx, cancel := context.WithCancel(m.ctx)
	state := &jobState{job: Job{ID: m.next, Key: key, JobRequest: cloneRequest(req), Status: "running", Stage: "Подготовка", Started: time.Now()}, cancel: cancel}
	m.jobs[state.job.ID] = state
	m.eventLocked(state, "Запуск: "+req.Label)
	if err := m.saveLocked(state); err != nil {
		delete(m.jobs, state.job.ID)
		cancel()
		return Job{}, err
	}
	if key != "" {
		m.keys[key] = state.job.ID
	}
	m.wg.Add(1)
	go m.run(ctx, state.job.ID, execute)
	return cloneJob(state.job), nil
}
func cloneRequest(r JobRequest) JobRequest {
	r.Targets = append([]string(nil), r.Targets...)
	r.Checks = append([]string(nil), r.Checks...)
	r.Options = append([]string(nil), r.Options...)
	return r
}
func cloneJob(j Job) Job {
	j.JobRequest = cloneRequest(j.JobRequest)
	j.Journal = append([]JobEvent(nil), j.Journal...)
	return j
}
func (m *Manager) eventLocked(s *jobState, msg string) {
	m.revision++
	s.job.Revision = m.revision
	s.job.Journal = append(s.job.Journal, JobEvent{Sequence: m.revision, Time: time.Now(), Message: msg})
	if len(s.job.Journal) > 500 {
		s.job.Journal = s.job.Journal[len(s.job.Journal)-500:]
	}
}
func (m *Manager) saveLocked(s *jobState) error {
	if m.store == nil {
		return nil
	}
	raw, err := json.Marshal(s.job)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = m.store.SaveJob(ctx, s.job.ID, raw)
	if err != nil {
		s.job.PersistenceError = err.Error()
	} else {
		s.job.PersistenceError = ""
		s.lastSaved = time.Now()
	}
	return err
}
func (m *Manager) run(ctx context.Context, id int, execute Executor) {
	defer m.wg.Done()
	var outcome Outcome
	var err error
	func() {
		defer func() {
			if recover() != nil {
				err = fmt.Errorf("исполнитель завершился аварийно")
			}
		}()
		outcome, err = execute(ctx, func(stage string, counts ...int) {
			m.mu.Lock()
			defer m.mu.Unlock()
			s := m.jobs[id]
			if s == nil {
				return
			}
			previous := s.job.Stage
			s.job.Stage = stage
			if len(counts) == 2 {
				s.job.Completed = max(0, counts[0])
				s.job.Total = max(0, counts[1])
			} else {
				s.job.Completed = 0
				s.job.Total = 0
			}
			if stage != previous || time.Since(s.lastSaved) >= time.Second {
				m.eventLocked(s, stage)
			} else {
				m.revision++
				s.job.Revision = m.revision
			}
			if time.Since(s.lastSaved) >= time.Second {
				_ = m.saveLocked(s)
			}
		})
	}()
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.jobs[id]
	if s == nil {
		return
	}
	wasCancelling := s.job.Status == "cancelling"
	executionCancelled := ctx.Err()
	s.cancel()
	s.job.Outcome = &outcome
	s.job.RunID = outcome.Result.RunID
	s.job.Findings = len(outcome.Result.Findings)
	s.job.Ended = time.Now()
	if outcome.ProjectID != 0 {
		s.job.ProjectID = outcome.ProjectID
	}
	s.job.Status = "done"
	s.job.Stage = "Готово"
	if err == nil && executionCancelled != nil {
		err = executionCancelled
	}
	// Cancellation before calling cancel above is determined by execution's error;
	// manager cancellation also sets the explicit cancelling state.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || wasCancelling {
		s.job.Status = "cancelled"
		s.job.Stage = "Отменено"
	} else if err != nil {
		s.job.Status = "failed"
		s.job.Stage = "Ошибка"
		s.job.Error = err.Error()
	} else if len(outcome.Result.Errors) > 0 {
		s.job.Stage = "Готово с ограничениями"
	}
	m.eventLocked(s, s.job.Stage)
	_ = m.saveLocked(s)
}
func (m *Manager) Get(id int) (Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.jobs[id]
	if !ok {
		return Job{}, false
	}
	return cloneJob(s.job), true
}
func (m *Manager) List() []Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Job, 0, len(m.jobs))
	for id := m.next; id > 0; id-- {
		if s := m.jobs[id]; s != nil {
			out = append(out, cloneJob(s.job))
		}
	}
	return out
}
func (m *Manager) Cancel(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.jobs[id]
	if !ok {
		return fmt.Errorf("задача не найдена")
	}
	if s.job.Status != "running" && s.job.Status != "cancelling" {
		return nil
	}
	s.job.Status = "cancelling"
	s.job.Stage = "Останавливается"
	m.eventLocked(s, s.job.Stage)
	s.cancel()
	return m.saveLocked(s)
}
func (m *Manager) Metadata(id int, scope string, checks, options []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.jobs[id]; s != nil {
		s.job.Scope = scope
		s.job.Checks = append([]string(nil), checks...)
		s.job.Options = append([]string(nil), options...)
		m.eventLocked(s, "Параметры запуска сохранены")
		_ = m.saveLocked(s)
	}
}
func (m *Manager) Active(projectID int64) bool {
	for _, j := range m.List() {
		if (projectID == 0 || j.ProjectID == projectID) && (j.Status == "running" || j.Status == "cancelling") {
			return true
		}
	}
	return false
}
func (m *Manager) Close() {
	m.mu.Lock()
	if !m.closing {
		m.closing = true
		m.cancel()
	}
	m.mu.Unlock()
	m.wg.Wait()
}
