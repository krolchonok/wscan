package js

import (
	"context"
	"fmt"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dssp/dssetup/v0"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"time"
)

// ReadMachineRole issues only DsRolerGetPrimaryDomainInformation, with no
// password/authenticate operation. An access denial is an unknown role.
func ReadMachineRole(parent context.Context, host string, port int, timeout time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(parent), timeout)
	defer cancel()
	c, e := dcerpc.Dial(ctx, host, dcerpc.WithEndpoint("ncacn_np:[lsarpc]"), dcerpc.WithSMBPort(port), dcerpc.WithMechanism(ssp.NTLM))
	if e != nil {
		return 0, e
	}
	defer c.Close(ctx)
	cli, e := dssetup.NewDssetupClient(ctx, c, dcerpc.WithInsecure())
	if e != nil {
		return 0, e
	}
	r, e := cli.GetPrimaryDomainInformation(ctx, &dssetup.GetPrimaryDomainInformationRequest{InfoLevel: dssetup.PrimaryDomainInfoLevelBasic})
	if e != nil {
		return 0, e
	}
	if r == nil || r.DomainInfo == nil {
		return 0, fmt.Errorf("DSROLE basic information absent")
	}
	info, ok := r.DomainInfo.GetValue().(*dssetup.PrimaryDomainInfoBasic)
	if !ok || info == nil {
		return 0, fmt.Errorf("DSROLE basic information absent")
	}
	role := int(info.MachineRole)
	if role < 0 || role > 5 {
		return 0, fmt.Errorf("invalid DSROLE %d", role)
	}
	return role, nil
}
