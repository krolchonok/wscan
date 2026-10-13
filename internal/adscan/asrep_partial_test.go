package adscan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
)

func TestASREPCancellationRetainsConfirmedHashAndExport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address, _ := asrepKDC(t, func(req messages.ASReq) ([]byte, error) {
		if req.ReqBody.CName.NameString[0] == "bob" {
			cancel()
			return nil, nil
		}
		rep := asrepFixture(req, 23)
		return rep.Marshal()
	})
	r, err := runASREPAt(ctx, address, "lab.example", []string{"alice", "bob"}, AccessOptions{RPS: 1000, ExportDir: t.TempDir()}, AccessReport{Host: "127.0.0.1", Mode: "asrep"})
	if !errors.Is(err, context.Canceled) || len(r.Checks) != 1 || r.Checks[0].State != "confirmed" || len(r.Artifacts) != 1 {
		t.Fatalf("partial result lost: %+v %v", r, err)
	}
}

func TestASREPRPSIncludesAESFallbackRequest(t *testing.T) {
	arrivals := make(chan time.Time, 2)
	address, _ := asrepKDC(t, func(req messages.ASReq) ([]byte, error) {
		arrivals <- time.Now()
		if req.ReqBody.EType[0] == 23 {
			e := messages.NewKRBError(req.ReqBody.SName, req.ReqBody.Realm, errorcode.KDC_ERR_ETYPE_NOSUPP, "")
			return e.Marshal()
		}
		rep := asrepFixture(req, 18)
		return rep.Marshal()
	})
	r, err := runASREPAt(context.Background(), address, "lab.example", []string{"alice"}, AccessOptions{RPS: 20}, AccessReport{Host: "127.0.0.1", Mode: "asrep"})
	if err != nil || len(r.Checks) != 1 || r.Checks[0].State != "confirmed" {
		t.Fatalf("%+v %v", r, err)
	}
	first, second := <-arrivals, <-arrivals
	if second.Sub(first) < 40*time.Millisecond {
		t.Fatalf("AES request bypassed RPS: %v", second.Sub(first))
	}
}
