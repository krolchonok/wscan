package adscan

import (
	"context"
	"time"
	js "wscan/internal/engine/js"
)

func windowsAccess(ctx context.Context, o AccessOptions) (AccessReport, error) {
	r := AccessReport{Host: o.Host, Mode: o.Mode}
	port := o.WinRMPort
	if port == 0 {
		port = 5985
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	data, e := js.CollectWindowsAudit(ctx, js.WinRMOptions{Host: o.Host, Port: port, HTTPS: port == 5986, Credential: o.Credential, Timeout: timeout})
	for _, c := range data.Checks {
		r.add(c.ID, c.ID, c.State, c.Severity, c.Evidence)
	}
	if data.Policy != nil {
		r.Policies = append(r.Policies, *data.Policy)
	}
	return r, e
}
