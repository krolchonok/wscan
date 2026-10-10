package js

import (
	"context"
	"fmt"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
)

// statusObjectNameInvalid is NTSTATUS 0xC0000033 (STATUS_OBJECT_NAME_INVALID)
// as the signed int32 go-msrpc's generated PathCompareResponse.Return uses.
const statusObjectNameInvalid int32 = -1073741773

// CheckMS08067 implements CVE-2008-4250 (MS08-067) detection via the same
// technique as nmap's smb-check-vulns.nse check_ms08_067 (itself crediting
// http://labs.portcullis.co.uk/application/ms08-067-check/): an srvsvc
// NetprPathCompare RPC call, over an anonymous/null SMB session, with a
// PathName1 crafted to walk the vulnerable path-canonicalization code
// without actually triggering the overflow payload an exploit would use.
//
// UNLIKE every other check in this package, this one is NOT side-effect
// free: nmap's own comment on the equivalent check says plainly "this CAN
// crash stuff (crash svchost and force a reboot)" with an observed ~5%
// crash rate in their own testing, and their script disables this specific
// check under its "safe" mode even though most of its other checks stay
// enabled there. This is why CVE-2008-4250.yaml carries the `exploit` tag
// and only runs when the operator has explicitly set
// domain.Project.AllowExploit — it is gated as a real risk-to-the-target
// check, not a passive detector like MS17-010/SMBGhost.
//
// Returns (vulnerable, error). A clean PATCHED signal (STATUS_OBJECT_NAME_INVALID)
// is vulnerable=false, err=nil. An RPC call that succeeds outright is the
// VULNERABLE signal. Any other outcome (unreachable, access denied, a
// non-Windows SMB server, Conficker's own UNKNOWN_57 infection marker) is
// inconclusive: vulnerable=false with a descriptive error, deliberately not
// reported as a positive match.
func CheckMS08067(parent context.Context, host string, port int, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(parent), timeout)
	defer cancel()

	if port <= 0 {
		port = 445
	}
	// dcerpc.WithMechanism(ssp.NTLM): the SMB named-pipe TRANSPORT's own
	// session-setup runs a real GSS-API handshake even for an
	// otherwise-insecure (AuthTypeNone) RPC bind, and its mechanism list is
	// drawn from the Dial-level options (via ExtractSecurityOptions), not
	// from the ambient gssapi security context — registering NTLM only on
	// the context (gssapi.NewSecurityContext(ctx, ssp.NTLM)) does not reach
	// it. A standalone (non-domain-joined) target has no Kerberos realm to
	// offer, so without this the client has no mechanism to match the
	// server's SPNEGO response against and fails with ErrBadMech
	// ("unsupported mechanism requested") before the RPC call ever runs.
	cc, err := dcerpc.Dial(ctx, host, dcerpc.WithEndpoint("ncacn_np:[srvsvc]"), dcerpc.WithSMBPort(port), dcerpc.WithMechanism(ssp.NTLM))
	if err != nil {
		return false, fmt.Errorf("srvsvc dial: %w", err)
	}
	defer cc.Close(ctx)

	cli, err := srvsvc.NewSrvsvcClient(ctx, cc, dcerpc.WithInsecure())
	if err != nil {
		return false, fmt.Errorf("srvsvc bind: %w", err)
	}

	resp, err := cli.PathCompare(ctx, &srvsvc.PathCompareRequest{
		PathName1: `\AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\..\n`,
		PathName2: `\n`,
		PathType:  1,
		Flags:     0,
	})
	if err == nil {
		// The generated client only returns a nil error when Return is
		// non-negative (see srvsvc's xxx_DefaultSrvsvcClient.PathCompare) —
		// for this call, that only happens on STATUS_SUCCESS: the malformed
		// path was accepted, exactly the vulnerable behavior.
		return true, nil
	}
	if resp != nil && resp.Return == statusObjectNameInvalid {
		return false, nil // PATCHED: the malformed path was correctly rejected.
	}
	return false, fmt.Errorf("inconclusive (not vulnerable, not confirmed patched): %w", err)
}
