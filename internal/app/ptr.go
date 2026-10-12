package app

import (
	"context"
	"fmt"
	"time"
	"wscan/internal/discovery"
	"wscan/internal/engine"
)

func (m Worker) runPTR(spec Spec) RunFunc {
	return func(ctx context.Context, emit Reporter) (engine.Result, error) {
		names, failures, err := discovery.ScanPTR(ctx, spec.Hosts, spec.DNSServer, m.current.DiscoveryConcurrency, m.current.DiscoveryRPS, time.Duration(m.current.TimeoutSeconds)*time.Second, func(done, total int) { emit("PTR через "+spec.DNSServer, done, total) })
		res := engine.Result{HostNames: names, Errors: failures}
		for host, values := range names {
			if len(values) > 0 {
				res.LiveHosts = append(res.LiveHosts, host)
			}
		}
		// Persist discoveries even when the user has switched to another project.
		if m.store != nil && err == nil {
			if saveErr := m.store.SavePTRHostNames(ctx, m.current.ID, names, spec.DNSServer); saveErr != nil {
				return res, saveErr
			}
			for _, host := range res.LiveHosts {
				if saveErr := m.store.AddTarget(ctx, m.current.ID, host); saveErr != nil {
					return res, saveErr
				}
			}
		}
		if err == nil && len(failures) > 0 && len(names) == 0 {
			err = fmt.Errorf("DNS-сервер не вернул ответов: %s", failures[0])
		}
		return res, err
	}
}
func (m Worker) RunPTR(spec Spec) RunFunc { return m.runPTR(spec) }
