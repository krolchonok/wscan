package discovery

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// ReverseHostNames looks up PTR records through the system DNS resolver.
// Missing names leave the IP unchanged; DNS does not determine host liveness.
func ReverseHostNames(ctx context.Context, hosts []string, timeout time.Duration) map[string][]string {
	if timeout <= 0 {
		timeout = time.Second
	}
	results := make(map[string][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)
	for i := 0; i < min(16, len(hosts)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				if net.ParseIP(host) == nil || ctx.Err() != nil {
					continue
				}
				queryCtx, cancel := context.WithTimeout(ctx, timeout)
				names, err := net.DefaultResolver.LookupAddr(queryCtx, host)
				cancel()
				if ctx.Err() != nil {
					continue
				}
				var clean []string
				if err == nil {
					for _, name := range names {
						name = strings.TrimSuffix(name, ".")
						if name != "" {
							clean = append(clean, name)
						}
					}
					clean = uniqueSorted(clean)
				}
				mu.Lock()
				results[host] = clean
				mu.Unlock()
			}
		}()
	}
feed:
	for _, host := range uniqueSorted(hosts) {
		select {
		case jobs <- host:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return results
}
