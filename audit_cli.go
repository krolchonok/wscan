package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"wscan/internal/adscan"
	"wscan/internal/app"
	"wscan/internal/catalog"
	"wscan/internal/domain"
	"wscan/internal/engine"
	"wscan/internal/storage"
)

func auditContext(duration time.Duration) (context.Context, func()) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(ctx, duration)
	return ctx, func() { cancel(); stop() }
}
func writeAuditJSON(path string, value any) error {
	var w io.Writer = os.Stdout
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
func parseAuditFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("неизвестные позиционные аргументы")
	}
	return nil
}
func runAuditCLI(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	mode := fs.String("mode", "directory", "directory, passpolicy, windows, dns, asrep или kerberoast")
	host := fs.String("host", "", "один IP/DNS хоста")
	realm := fs.String("domain", "", "DNS-домен AD или DNS-зона; для windows необязательно")
	user := fs.String("username", "", "известная учётка; WSCAN_AUDIT_PASSWORD / WSCAN_AUDIT_NTHASH")
	credDomain := fs.String("credential-domain", "", "область учётки; по умолчанию --domain")
	port := fs.Int("port", 0, "LDAP: 389/636; WinRM: 5985/5986; DNS: 53")
	limit := fs.Int("max-objects", 5000, "лимит LDAP-объектов")
	duration := fs.Duration("timeout", 2*time.Minute, "общий таймаут")
	output := fs.String("output", "", "новый JSON-файл, иначе stdout")
	users := fs.String("users", "", "AS-REP: имена через запятую; иначе LDAP")
	usersFile := fs.String("users-file", "", "AS-REP: файл имён по строке")
	spns := fs.String("spns", "", "Kerberoast: SPN через запятую; иначе активные пользовательские SPN из LDAP")
	spnsFile := fs.String("spns-file", "", "Kerberoast: файл SPN по строке")
	noPreauthUser := fs.String("nopreauth-user", "", "Kerberoast без пароля: известный логин с отключённой pre-auth")
	tgtFile := fs.String("tgt-file", "", "Kerberoast с готовым TGT: .kirbi или .ccache v3/v4")
	etypes := fs.String("tgs-etypes", "", "Kerberoast: 18,17,23; без pre-auth по умолчанию 23,18,17")
	rps := fs.Int("rps", 2, "Kerberos: запросов/с, 1–20")
	exportDir := fs.String("export-dir", "", "каталог хешей; по умолчанию kerberos-artifacts рядом с JSON")
	if err := parseAuditFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *host == "" || strings.ContainsAny(*host, "/\\ \t\r\n") {
		return fmt.Errorf("укажи --host без CIDR и порта")
	}
	if *duration <= 0 {
		return fmt.Errorf("--timeout должен быть положительным")
	}
	if *mode != "directory" && *mode != "passpolicy" && *mode != "windows" && *mode != "dns" && *mode != "asrep" && *mode != "kerberoast" {
		return fmt.Errorf("неподдерживаемый --mode")
	}
	if *mode != "windows" && *realm == "" {
		return fmt.Errorf("укажи --domain")
	}
	if *mode == "windows" && *user == "" {
		return fmt.Errorf("windows требует --username")
	}
	alternateRoast := *noPreauthUser != "" || *tgtFile != ""
	if alternateRoast && *mode != "kerberoast" {
		return fmt.Errorf("--nopreauth-user и --tgt-file используются только с kerberoast")
	}
	if alternateRoast && (*user != "" || (*noPreauthUser != "" && *tgtFile != "")) {
		return fmt.Errorf("выбери один режим: --username, --nopreauth-user или --tgt-file")
	}
	if *mode == "kerberoast" && *user == "" && !alternateRoast {
		return fmt.Errorf("kerberoast требует --username и известный пароль/NT hash")
	}
	if *rps < 1 || *rps > 20 || *limit < 1 || *limit > 50000 {
		return fmt.Errorf("--rps: 1–20; --max-objects: 1–50000")
	}
	if *output != "" {
		if _, err := os.Stat(*output); err == nil {
			return fmt.Errorf("файл результата уже существует")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	domainName := *credDomain
	if domainName == "" {
		domainName = *realm
	}
	secret, present := os.LookupEnv("WSCAN_AUDIT_PASSWORD")
	cred := domain.Credential{Type: "password", Username: *user, Domain: domainName, Secret: secret}
	if hash := os.Getenv("WSCAN_AUDIT_NTHASH"); hash != "" {
		cred.Type = "ntlm-hash"
		cred.Secret = hash
		present = true
	}
	if *user != "" && !present {
		return fmt.Errorf("задай WSCAN_AUDIT_PASSWORD или WSCAN_AUDIT_NTHASH")
	}
	o := adscan.AccessOptions{Host: *host, Domain: *realm, Mode: *mode, Credential: cred, MaxObjects: *limit, Timeout: 30 * time.Second}
	if alternateRoast {
		o.Credential = domain.Credential{}
		o.NoPreauthUser, o.TGTFile = *noPreauthUser, *tgtFile
	}
	if *mode == "asrep" || *mode == "kerberoast" {
		o.RPS, o.Timeout, o.ExportDir = *rps, 5*time.Second, *exportDir
		if o.ExportDir == "" {
			o.ExportDir = filepath.Join(filepath.Dir(*output), "kerberos-artifacts")
		}
		var err error
		if *mode == "asrep" {
			o.Users, err = auditList(*users, *usersFile, *limit)
			if *spns != "" || *spnsFile != "" {
				return fmt.Errorf("--spns используются только с kerberoast")
			}
		} else {
			o.SPNs, err = auditList(*spns, *spnsFile, *limit)
			if *users != "" || *usersFile != "" {
				return fmt.Errorf("для kerberoast укажи --spns, а не --users")
			}
			for _, value := range strings.Split(*etypes, ",") {
				if *etypes == "" {
					break
				}
				n, e := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
				if e != nil || (n != 17 && n != 18 && n != 23) {
					return fmt.Errorf("--tgs-etypes: только 17,18,23")
				}
				o.TGSEtypes = append(o.TGSEtypes, int32(n))
			}
		}
		if err != nil {
			return err
		}
		if (*mode == "asrep" && (*users != "" || *usersFile != "") && len(o.Users) == 0) || (*mode == "kerberoast" && (*spns != "" || *spnsFile != "") && len(o.SPNs) == 0) {
			return fmt.Errorf("явно указанный список пуст")
		}
		if *mode == "kerberoast" {
			if err := adscan.ValidateKerberoastOptions(&o); err != nil {
				return err
			}
		}
	}
	switch *mode {
	case "windows":
		o.WinRMPort = *port
		if *port != 0 && *port != 5985 && *port != 5986 {
			return fmt.Errorf("WinRM-порт: 5985/5986")
		}
	case "dns":
		o.DNSPort = *port
		if *port < 0 || *port > 65535 {
			return fmt.Errorf("неверный DNS-порт")
		}
	default:
		o.LDAPPort = *port
		if *mode == "asrep" && *port == 0 {
			o.LDAPPort = 389
		}
	}
	ctx, stop := auditContext(*duration)
	defer stop()
	r, err := adscan.RunAccess(ctx, o)
	return errors.Join(writeAuditJSON(*output, struct {
		Report adscan.AccessReport
		Error  string
	}{r, cliError(err)}), err)
}

func auditList(inline, path string, limit int) ([]string, error) {
	if inline != "" && path != "" {
		return nil, fmt.Errorf("выбери список либо файл списка")
	}
	if path != "" {
		inline = "@" + path
	}
	return adscan.ReadKerberosList(inline, limit)
}
func cliError(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func runADScanCLI(args []string) error {
	fs := flag.NewFlagSet("ad-scan", flag.ContinueOnError)
	scope := fs.String("scope", "", "IP/частные CIDR через запятую")
	database := fs.String("db", "ad-audit.db", "SQLite для отдельного проекта аудита")
	output := fs.String("output", "", "новый JSON-файл, иначе stdout")
	library := fs.String("library", "", "каталог библиотеки проверок")
	duration := fs.Duration("timeout", 5*time.Minute, "общий таймаут")
	if err := parseAuditFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(*scope) == "" || *duration <= 0 {
		return fmt.Errorf("укажи --scope и положительный --timeout")
	}
	ctx, stop := auditContext(*duration)
	defer stop()
	s, err := storage.Open(*database)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := os.Chmod(*database, 0600); err != nil {
		return err
	}
	p := domain.Project{Name: "AD audit", RPS: 5, Concurrency: 4, TimeoutSeconds: 5}
	cat := catalog.NewWithLibrary("", *library)
	scanner := engine.New(s, engine.Config{LibraryDir: cat.LibraryDir(), RPS: 5, Concurrency: 4, TimeoutSeconds: 5})
	w := app.NewWorker(s, cat, scanner, p, nil, nil, true, adscan.DNSOptions{})
	result, details, id, name, err := w.RunADScan(ctx, strings.ReplaceAll(*scope, ",", " "), func(stage string, counts ...int) { fmt.Fprintln(os.Stderr, stage, counts) })
	return errors.Join(writeAuditJSON(*output, struct {
		Result             engine.Result
		Details            *adscan.Result
		ProjectID          int64
		ProjectName, Error string
	}{result, details, id, name, cliError(err)}), err)
}

func runLocalSMBCLI(args []string) error {
	fs := flag.NewFlagSet("local-smb", flag.ContinueOnError)
	targets := fs.String("targets", "", "IP/DNS машин через запятую; DC будут исключены")
	username := fs.String("username", "", "одно локальное имя без домена")
	userlist := fs.String("users", "", "файл локальных имён, до 5000 строк")
	passwordlist := fs.String("passwords", "", "файл паролей; иначе одна пара из WSCAN_AUDIT_PASSWORD")
	database := fs.String("db", "local-audit.db", "SQLite с постоянным журналом попыток")
	output := fs.String("output", "", "новый JSON-файл, иначе stdout")
	port := fs.Int("port", 445, "SMB TCP-порт")
	rps := fs.Int("rps", 1, "общий RPS, 1–20")
	maximum := fs.Int("max-failures", 3, "лимит ошибок каждой локальной учётки, 1–3")
	duration := fs.Duration("timeout", 5*time.Minute, "общий таймаут")
	library := fs.String("library", "", "библиотека NSE для резервного определения клиентской ОС")
	policyReport := fs.String("policy-report", "", "свежий JSON Windows-аудита с локальной политикой; до 15 минут")

	if err := parseAuditFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *targets == "" || *port < 1 || *port > 65535 || *rps < 1 || *rps > 20 || *maximum < 1 || *maximum > 3 || *duration <= 0 {
		return fmt.Errorf("проверь --targets/--port/--rps/--max-failures/--timeout")
	}
	if (*username == "") == (*userlist == "") {
		return fmt.Errorf("укажи ровно один из --username/--users")
	}
	users := []string{*username}
	if *userlist != "" {
		f, err := os.Open(*userlist)
		if err != nil {
			return err
		}
		defer f.Close()
		users = nil
		scan := bufio.NewScanner(f)
		for scan.Scan() {
			if u := strings.TrimSpace(scan.Text()); u != "" {
				users = append(users, u)
			}
			if len(users) > 5000 {
				return fmt.Errorf("слишком много пользователей")
			}
		}
		if err := scan.Err(); err != nil {
			return err
		}
	}
	var passwords io.Reader
	if *passwordlist != "" {
		f, err := os.Open(*passwordlist)
		if err != nil {
			return err
		}
		defer f.Close()
		passwords = f
	} else {
		secret, present := os.LookupEnv("WSCAN_AUDIT_PASSWORD")
		if !present {
			return fmt.Errorf("задай WSCAN_AUDIT_PASSWORD или --passwords")
		}
		if strings.ContainsAny(secret, "\r\n") {
			return fmt.Errorf("пароль не должен содержать перевод строки")
		}
		passwords = strings.NewReader(secret + "\n")
	}
	var services []domain.Service
	for _, host := range strings.Split(*targets, ",") {
		host = strings.TrimSpace(host)
		if host == "" || strings.ContainsAny(host, "/\\ \t\r\n") {
			return fmt.Errorf("цели задаются отдельными IP/DNS без CIDR")
		}
		services = append(services, domain.Service{Host: host, Port: *port, Protocol: "smb"})
	}
	if *library == "" {
		root, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		*library = findLibraryDir(filepath.Join(root, "wscan"))
	}
	ctx, stop := auditContext(*duration)
	defer stop()
	s, err := storage.Open(*database)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := os.Chmod(*database, 0600); err != nil {
		return err
	}
	// Reuse the project so a later invocation cannot reset recorded lockout budgets.
	projects, err := s.ListProjects(ctx)
	if err != nil {
		return err
	}
	var p domain.Project
	for _, candidate := range projects {
		if candidate.Name == "Local SMB audit" {
			p = candidate
			break
		}
	}
	if p.ID == 0 {
		p.ID, err = s.CreateProject(ctx, "Local SMB audit")
		if err != nil {
			return err
		}
	}
	p.AllowCredentialAttack = true
	p.LockoutMaxAttempts = *maximum
	scanner := engine.New(s, engine.Config{RPS: *rps, Concurrency: 1, TimeoutSeconds: 8, LibraryDir: *library})
	if *policyReport != "" {
		f, err := os.Open(*policyReport)
		if err != nil {
			return err
		}
		defer f.Close()
		stat, err := f.Stat()
		if err != nil {
			return err
		}
		if stat.Size() > 1024*1024 || time.Since(stat.ModTime()) > 15*time.Minute {
			return fmt.Errorf("политика должна быть из свежего отчёта, до 1 МиБ")
		}
		var payload struct{ Report adscan.AccessReport }
		if err := json.NewDecoder(io.LimitReader(f, 1024*1024)).Decode(&payload); err != nil {
			return err
		}
		accepted := 0
		for _, policy := range payload.Report.Policies {
			for _, service := range services {
				if policy.DN == service.Host && policy.Source == "local" && policy.LockoutThreshold != nil {
					scanner.RememberLocalPolicy(p.ID, policy)
					accepted++
				}
			}
		}
		if accepted == 0 {
			return fmt.Errorf("отчёт не содержит локальной политики выбранных машин; доменная политика не применяется")
		}
	}
	result, err := scanner.LocalDictionary(ctx, p, services, users, passwords, engine.LocalSprayOptions{}, func(a domain.AuthAttempt) {
		fmt.Fprintf(os.Stderr, "%s %s\\%s success=%v skipped=%v\n", a.Target, a.Domain, a.Username, a.Success, a.Skipped)
	})
	return errors.Join(writeAuditJSON(*output, struct {
		Result *engine.SprayResult
		Error  string
	}{result, cliError(err)}), err)
}
