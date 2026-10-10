package js

import (
	"context"
	"fmt"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/nrpc/logon/v1"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

// ZerologonMaxAttempts matches the original PoC (https://github.com/dirkjanm/
// CVE-2020-1472) and nxc's own zerologon module: the AES-CFB8 all-zero-IV
// weakness succeeds on average every ~256 attempts against a vulnerable DC;
// 2000 keeps the false-negative rate at roughly 0.04%.
const ZerologonMaxAttempts = 2000

// CheckZerologon implements CVE-2020-1472 (Zerologon) detection: repeated
// NetrServerAuthenticate3 calls with an all-zero client credential, over an
// anonymous (unauthenticated) DCE-RPC bind to the Netlogon interface —
// exactly the dirkjanm/nxc technique. It never calls NetrServerPasswordSet,
// so a vulnerable DC's machine account password is never touched: this is
// detection only, with no side effects regardless of outcome.
//
// computerName must be the target DC's own NetBIOS computer name (see
// ResolveNetBIOSName) — the protocol rejects an IP address or any other
// name outright, long before the vulnerability check itself runs.
func CheckZerologon(parent context.Context, host, computerName string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(parent), timeout)
	defer cancel()

	cc, err := dcerpc.Dial(ctx, host, epm.EndpointMapper(ctx, host))
	if err != nil {
		return false, fmt.Errorf("dce-rpc dial: %w", err)
	}
	defer cc.Close(ctx)

	cli, err := logon.NewLogonClient(ctx, cc, dcerpc.WithInsecure(), dcerpc.WithEndpoint("ncacn_ip_tcp:"))
	if err != nil {
		return false, fmt.Errorf("netlogon bind: %w", err)
	}

	zero8 := make([]byte, 8)
	primaryName := `\\` + computerName
	accountName := computerName + "$"

	// A failure here means this isn't a reachable Netlogon/DC endpoint at
	// all — abort rather than retry (matches nxc: DCERPCException here means
	// "probably not a DC").
	if _, err := cli.RequestChallenge(ctx, &logon.RequestChallengeRequest{
		PrimaryName:     primaryName,
		ComputerName:    computerName,
		ClientChallenge: &logon.Credential{Data: zero8},
	}); err != nil {
		return false, fmt.Errorf("netlogon challenge failed (likely not a domain controller): %w", err)
	}

	for attempt := 0; attempt < ZerologonMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		resp, err := cli.Authenticate3(ctx, &logon.Authenticate3Request{
			PrimaryName:       primaryName,
			AccountName:       accountName,
			SecureChannelType: logon.SecureChannelTypeServerSecureChannel,
			ComputerName:      computerName,
			ClientCredential:  &logon.Credential{Data: zero8},
			NegotiateFlags:    0x212fffff,
		})
		if err == nil {
			// The generated client only returns a nil error when the
			// protocol-level Return code is non-negative — see
			// xxx_DefaultLogonClient.Authenticate3 — which for this call
			// only happens on STATUS_SUCCESS (0) in practice.
			return true, nil
		}
		if resp == nil {
			// A transport-level failure (dropped connection etc.), not a
			// protocol-level rejection — stop instead of burning through
			// the remaining attempts against a connection that's gone.
			return false, fmt.Errorf("netlogon authenticate: %w", err)
		}
		// resp != nil && err != nil: a clean protocol rejection (expected
		// STATUS_ACCESS_DENIED on a patched DC) — keep trying.
	}
	return false, nil
}
