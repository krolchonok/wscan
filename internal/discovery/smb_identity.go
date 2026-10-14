package discovery

import (
	"context"
	"time"
	"wscan/internal/smbidentity"
)

type SMBIdentity = smbidentity.Identity

func ProbeSMBIdentity(ctx context.Context, host string, port int, timeout time.Duration) (SMBIdentity, error) {
	return smbidentity.Probe(ctx, host, port, timeout)
}
