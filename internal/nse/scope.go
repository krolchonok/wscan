package nse

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func (c *control) bindScope(host HostInfo, ports []PortInfo) {
	c.allowedHosts = map[string]bool{}
	for _, name := range []string{host.IP, host.Name} {
		if name != "" {
			c.allowedHosts[strings.ToLower(strings.Trim(name, "[]"))] = true
		}
	}
	c.allowedPorts = map[string]bool{}
	for _, p := range ports {
		protocol := strings.ToLower(p.Protocol)
		if protocol == "" {
			protocol = "tcp"
		}
		c.allowedPorts[protocol+":"+strconv.Itoa(p.Number)] = true
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) { return c.dial(network, address) }}
	c.client.Transport = transport
	c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		if err := c.checkScope("tcp", requestEndpoint(req)); err != nil {
			return http.ErrUseLastResponse
		}
		return nil
	}
}
func requestEndpoint(req *http.Request) string {
	port := req.URL.Port()
	if port == "" {
		port = "80"
		if req.URL.Scheme == "https" {
			port = "443"
		}
	}
	return net.JoinHostPort(req.URL.Hostname(), port)
}
func (c *control) checkScope(network, address string) error {
	if c.allowedHosts == nil {
		return nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	network = strings.TrimSuffix(strings.TrimSuffix(network, "4"), "6")
	if !c.allowedHosts[strings.ToLower(strings.Trim(host, "[]"))] || !c.allowedPorts[network+":"+port] {
		return fmt.Errorf("NSE: запрос %s %s вне выбранных сервисов", network, address)
	}
	return nil
}

// RunWithArgs copies configuration, so credentials are confined to this script
// and never stored on a shared Runner or carried between Lua states.
func (r *Runner) RunWithArgs(ctx context.Context, path string, host HostInfo, ports []PortInfo, args map[string]string) ([]ScriptResult, bool, error) {
	cfg := r.cfg
	cfg.Args = map[string]string{}
	for k, v := range r.cfg.Args {
		cfg.Args[k] = v
	}
	for k, v := range args {
		cfg.Args[k] = v
	}
	cfg.SelectedServicesOnly = true
	return New(r.libraryDir, cfg).Run(ctx, path, host, ports)
}
