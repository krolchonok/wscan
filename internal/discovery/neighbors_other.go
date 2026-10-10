//go:build !linux

package discovery

import "context"

func confirmedNeighborHosts(_ context.Context, _ []string, _ map[string]bool) []string {
	return nil
}
