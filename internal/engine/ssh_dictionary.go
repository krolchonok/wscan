package engine

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"wscan/internal/domain"
)

type SSHDictionaryOptions struct {
	Username, Userlist, Passwordlist string
	Delay                            time.Duration
	Unlimited                        bool
	RPS, Concurrency                 int
}
type SSHDictionaryAttempt struct {
	Attempt   domain.AuthAttempt
	Password  string
	Cancelled bool
}
type SSHDictionaryResult struct {
	Attempts              []SSHDictionaryAttempt
	Tried, Blocked, Found int
}

func sshDictionaryUsers(o SSHDictionaryOptions) ([]string, error) {
	users := []string{strings.TrimSpace(o.Username)}
	if o.Userlist != "" {
		f, err := os.Open(o.Userlist)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		users = nil
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 65536)
		for scanner.Scan() {
			users = append(users, strings.TrimSpace(scanner.Text()))
			if len(users) > 10000 {
				return nil, fmt.Errorf("словарь пользователей превышает 10000 строк")
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	unique := []string{}
	seen := map[string]bool{}
	for _, user := range users {
		if user != "" && !strings.HasPrefix(user, "#") && !seen[user] {
			unique = append(unique, user)
			seen[user] = true
		}
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("укажи пользователя или словарь пользователей")
	}
	return unique, nil
}

// SSHDictionary queues passwords across active users into a bounded worker pool.
// RPS and Delay constrain global attempt starts. Unlimited explicitly
// bypasses only the project failure threshold for this dictionary run.
func (e *Engine) SSHDictionary(ctx context.Context, p domain.Project, target domain.Service, o SSHDictionaryOptions, progress func(SSHDictionaryAttempt)) (SSHDictionaryResult, error) {
	result := SSHDictionaryResult{}
	if !p.AllowCredentialAttack {
		return result, fmt.Errorf("credential-атаки выключены в настройках проекта")
	}
	if target.Host == "" || target.Port < 1 || target.Port > 65535 {
		return result, fmt.Errorf("укажи хост и TCP-порт SSH")
	}
	users, err := sshDictionaryUsers(o)
	if err != nil {
		return result, err
	}
	if o.Passwordlist == "" {
		return result, fmt.Errorf("укажи файл словаря паролей")
	}
	file, err := os.Open(o.Passwordlist)
	if err != nil {
		return result, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 65536)
	target.Protocol = "ssh"
	runEngine := *e
	if p.TimeoutSeconds > 0 {
		runEngine.config.TimeoutSeconds = p.TimeoutSeconds
	}
	if o.Delay < 0 || o.RPS < 0 || o.Concurrency < 0 || o.Concurrency > 64 {
		return result, fmt.Errorf("пауза и RPS должны быть неотрицательными; потоки: 1–64")
	}
	workers := o.Concurrency
	if workers == 0 {
		workers = 1
	}
	// Serialize store access and limited attempts per account; unlimited runs may
	// authenticate concurrently against the same account.
	safeStore := &sshDictionaryStore{Saver: e.store}
	runEngine.store = safeStore
	var mu sync.Mutex
	inactive := map[string]bool{}
	accountLocks := map[string]*sync.Mutex{}
	for _, u := range users {
		accountLocks[u] = &sync.Mutex{}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	accountContexts := map[string]context.Context{}
	accountCancels := map[string]context.CancelFunc{}
	for _, user := range users {
		accountCtx, stop := context.WithCancel(runCtx)
		accountContexts[user] = accountCtx
		accountCancels[user] = stop
		defer stop()
	}
	interval := o.Delay
	if o.RPS > 0 {
		rateInterval := time.Second / time.Duration(o.RPS)
		if rateInterval > interval {
			interval = rateInterval
		}
	}
	var tokens <-chan time.Time
	if interval > 0 {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		tokens = ticker.C
	}
	type job struct{ user, password string }
	jobs := make(chan job, workers)
	var wg sync.WaitGroup
	var firstErr error
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
		cancel()
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if runCtx.Err() != nil {
					return
				}
				lock := accountLocks[item.user]
				if !o.Unlimited {
					lock.Lock()
				}
				process := func() {
					accountCtx := accountContexts[item.user]
					mu.Lock()
					skip := inactive[item.user]
					mu.Unlock()
					if skip {
						return
					}
					if tokens != nil {
						select {
						case <-accountCtx.Done():
							return
						case <-tokens:
						}
					}
					mu.Lock()
					skip = inactive[item.user]
					mu.Unlock()
					if skip || accountCtx.Err() != nil {
						return
					}
					cred := domain.Credential{Type: "password", Username: item.user, Secret: item.password}
					res, err := runEngine.sprayCredentials(accountCtx, p, []domain.Service{target}, []domain.Credential{cred}, true, o.Unlimited)
					mu.Lock()
					if res != nil && len(res.Attempts) > 0 {
						record := SSHDictionaryAttempt{Attempt: res.Attempts[0]}
						record.Cancelled = accountCtx.Err() != nil && inactive[item.user] && !record.Attempt.Success
						if !record.Attempt.Skipped {
							record.Password = item.password
						}
						if record.Attempt.Success {
							if !inactive[item.user] {
								result.Found++
							}
							inactive[item.user] = true
							accountCancels[item.user]()
						} else if record.Attempt.Skipped {
							if !inactive[item.user] {
								result.Blocked++
							}
							inactive[item.user] = true
							accountCancels[item.user]()
						}
						if !record.Attempt.Skipped {
							result.Tried++
						}
						result.Attempts = append(result.Attempts, record)
						if progress != nil {
							progress(record)
						}
						if err == nil && record.Attempt.Error != "" && !sshAuthenticationRejected(record.Attempt.Error) && accountCtx.Err() == nil {
							err = fmt.Errorf("SSH: %s", record.Attempt.Error)
						}
					}
					mu.Unlock()
					if err != nil && accountCtx.Err() == nil {
						fail(err)
					}
				}
				process()
				if !o.Unlimited {
					lock.Unlock()
				}
			}
		}()
	}
	passwords := 0
feed:
	for scanner.Scan() {
		passwords++
		password := strings.TrimSuffix(scanner.Text(), "\r")
		for _, user := range users {
			mu.Lock()
			skip := inactive[user]
			allDone := len(inactive) == len(users)
			mu.Unlock()
			if allDone {
				break feed
			}
			if skip {
				continue
			}
			select {
			case <-runCtx.Done():
				break feed
			case jobs <- job{user, password}:
			}
		}
	}
	scanErr := scanner.Err()
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if firstErr != nil {
		return result, firstErr
	}
	if scanErr != nil {
		return result, scanErr
	}
	if passwords == 0 {
		return result, fmt.Errorf("словарь паролей пуст")
	}
	return result, nil
}

type sshDictionaryStore struct {
	Saver
	mu sync.Mutex
}

func (s *sshDictionaryStore) RecordAttempt(ctx context.Context, p int64, target, user, protocol string, success bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Saver.RecordAttempt(ctx, p, target, user, protocol, success)
}
func (s *sshDictionaryStore) RecentFailureCount(ctx context.Context, p int64, user string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Saver.RecentFailureCount(ctx, p, user, since)
}

func sshAuthenticationRejected(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "unable to authenticate") || strings.Contains(lower, "no supported methods remain") || strings.Contains(lower, "permission denied")
}
