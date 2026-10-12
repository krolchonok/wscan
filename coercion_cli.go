package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"wscan/internal/adscan"
	"wscan/internal/domain"
)

func runCoercionCLI(args []string) error {
	fs := flag.NewFlagSet("coerce", flag.ContinueOnError)
	targets := fs.String("targets", "", "IP/DNS машин через запятую")
	callback := fs.String("callback", "", "локальный IPv4 приёмника")
	discovery := fs.Bool("discovery", false, "только RPC bind, без Coerce")
	debug := fs.Bool("debug", false, "подробные SMB/NTLM события без содержимого полей")
	logPath := fs.String("log", "", "файл диагностического журнала (append, 0600)")
	listen := fs.Bool("listen", false, "только приёмник; Ctrl+C завершает и выводит отчёт")
	duration := fs.Duration("duration", time.Minute, "максимальная длительность запуска")
	timeout := fs.Duration("timeout", 8*time.Second, "таймаут одного RPC метода")
	username := fs.String("username", "", "учётка для RPC; пароль из WSCAN_COERCE_PASSWORD, NTLM-хеш из WSCAN_COERCE_NTHASH")
	domainName := fs.String("domain", "", "домен учётки")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("неизвестные аргументы")
	}
	if *targets == "" {
		return fmt.Errorf("укажи --targets")
	}
	if *listen && *discovery {
		return fmt.Errorf("--listen и --discovery несовместимы")
	}
	if *duration < time.Second || *duration > 24*time.Hour {
		return fmt.Errorf("--duration: 1s–24h")
	}
	hosts := strings.Split(*targets, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}
	cred := domain.Credential{Type: "password", Username: *username, Secret: os.Getenv("WSCAN_COERCE_PASSWORD")}
	if hash := os.Getenv("WSCAN_COERCE_NTHASH"); hash != "" {
		cred.Type = "ntlm-hash"
		cred.Secret = hash
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, *duration)
	defer cancel()
	var logFile *os.File
	if *logPath != "" {
		if err := os.MkdirAll(filepath.Dir(*logPath), 0700); err != nil {
			return err
		}
		var err error
		logFile, err = os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer logFile.Close()
		if err = logFile.Chmod(0600); err != nil {
			return err
		}
	}
	var logMu sync.Mutex
	var logErr error
	progress := func(s string) {
		logMu.Lock()
		defer logMu.Unlock()
		fmt.Fprintln(os.Stderr, s)
		if logFile != nil && logErr == nil {
			_, logErr = fmt.Fprintln(logFile, s)
			if logErr != nil {
				cancel()
			}
		}
	}
	var reports []adscan.AccessReport
	var err error
	if *listen {
		reports, err = adscan.RunResponderWithOptions(ctx, *callback, hosts, adscan.ResponderOptions{Debug: *debug}, progress)
	} else {
		reports, err = adscan.RunCoercion(ctx, adscan.CoercionOptions{ReceiverDebug: *debug, Targets: hosts, Callback: *callback, DiscoverOnly: *discovery, Timeout: *timeout, Credential: adscan.AccessOptions{Domain: *domainName, Credential: cred}}, progress)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if e := encoder.Encode(reports); e != nil {
		return e
	}
	return errors.Join(err, logErr)
}
