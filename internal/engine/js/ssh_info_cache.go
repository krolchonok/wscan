package js

import (
	"context"
	"sync"
)

type sshInfoCacheKey struct{}
type sshInfoEntry struct {
	done chan struct{}
	info *HandshakeInfo
	err  error
}
type sshInfoCache struct {
	mu      sync.Mutex
	entries map[string]*sshInfoEntry
}

// WithSSHInfoCache shares one successful information handshake per endpoint
// within a scan. Credential authentication is never cached.
func WithSSHInfoCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, sshInfoCacheKey{}, &sshInfoCache{entries: map[string]*sshInfoEntry{}})
}

func (c *sshInfoCache) get(ctx context.Context, key string, fetch func() (*HandshakeInfo, error)) (*HandshakeInfo, error) {
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-entry.done:
			return cloneSSHInfo(entry.info), entry.err
		}
	}
	entry := &sshInfoEntry{done: make(chan struct{})}
	c.entries[key] = entry
	c.mu.Unlock()
	entry.info, entry.err = fetch()
	c.mu.Lock()
	if entry.err != nil {
		delete(c.entries, key)
	}
	close(entry.done)
	c.mu.Unlock()
	return cloneSSHInfo(entry.info), entry.err
}

func cloneSSHInfo(info *HandshakeInfo) *HandshakeInfo {
	if info == nil {
		return nil
	}
	copyInfo := *info
	copyInfo.UserAuth = append([]string{}, info.UserAuth...)
	if info.ServerID != nil {
		id := *info.ServerID
		copyInfo.ServerID = &id
	}
	if info.ServerKex != nil {
		kex := *info.ServerKex
		kex.KexAlgos = append([]string{}, kex.KexAlgos...)
		kex.CiphersClientServer = append([]string{}, kex.CiphersClientServer...)
		kex.CiphersServerClient = append([]string{}, kex.CiphersServerClient...)
		kex.MACsClientServer = append([]string{}, kex.MACsClientServer...)
		kex.MACsServerClient = append([]string{}, kex.MACsServerClient...)
		copyInfo.ServerKex = &kex
	}
	return &copyInfo
}
