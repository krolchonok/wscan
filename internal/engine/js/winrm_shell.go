package js

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/masterzen/winrm"
)

type WinRMShellOutput struct {
	Output    string `json:"output"`
	Directory string `json:"directory"`
	ExitCode  int    `json:"exit_code"`
}

type shellReply struct {
	value WinRMShellOutput
	err   error
}

// WinRMShell retains a PowerShell process, so directory and variables persist.
// Only one Run may be outstanding. Close is asynchronous and bounded.
type WinRMShell struct {
	command    *winrm.Command
	shell      *winrm.Shell
	cancel     context.CancelFunc
	marker     string
	replies    chan shellReply
	mu         sync.Mutex
	once       sync.Once
	closed     chan struct{}
	stderr     cappedOutput
	stderrDone chan struct{}
}

func OpenWinRMShell(ctx context.Context, o WinRMOptions, directory string) (*WinRMShell, error) {
	ctx, cancel := context.WithCancel(ctx)
	client, err := newInteractionWinRM(ctx, o)
	if err != nil {
		cancel()
		return nil, err
	}
	client.Parameters.Timeout = "PT1S"
	shell, err := client.CreateShell()
	if err != nil {
		cancel()
		return nil, err
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		_ = shell.Close()
		cancel()
		return nil, err
	}
	marker := "WSCAN:" + hex.EncodeToString(token) + ":"
	script := `[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';Set-Location -LiteralPath ` + psLiteral(directory) + `;
 while(($__wscan_line=[Console]::ReadLine()) -ne $null) {
 $__wscan_code=0;$global:LASTEXITCODE=0;
 try {$__wscan_script=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__wscan_line));$__wscan_output=Invoke-Expression $__wscan_script 2>&1 | Out-String -Width 200;$__wscan_code=$global:LASTEXITCODE}
 catch {$__wscan_output=$_ | Out-String;$__wscan_code=1};
 if ($__wscan_output.Length -gt 262144) {$__wscan_output=$__wscan_output.Substring(0,262144)+"[Вывод обрезан]"};
 $__wscan_reply=[pscustomobject]@{output=[string]$__wscan_output;directory=(Get-Location).Path;exit_code=[int]$__wscan_code}|ConvertTo-Json -Compress;
 [Console]::WriteLine(` + psLiteral(marker) + `+$__wscan_reply);[Console]::Out.Flush()
 }`
	command, err := shell.ExecuteWithContext(ctx, winrm.Powershell(script))
	if err != nil {
		_ = shell.Close()
		cancel()
		return nil, err
	}
	session := &WinRMShell{command: command, shell: shell, cancel: cancel, marker: marker, replies: make(chan shellReply, 1), closed: make(chan struct{}), stderr: cappedOutput{limit: 64 * 1024}, stderrDone: make(chan struct{})}
	go func() { defer close(session.stderrDone); _, _ = io.Copy(&session.stderr, command.Stderr) }()
	go session.readReplies(ctx)
	return session, nil
}

func (s *WinRMShell) readReplies(ctx context.Context) {
	defer close(s.replies)
	scanner := bufio.NewScanner(s.command.Stdout)
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	var extra cappedOutput
	extra.limit = 256 * 1024
	for scanner.Scan() {
		line := scanner.Text()
		at := strings.Index(line, s.marker)
		if at < 0 {
			_, _ = extra.Write([]byte(line + "\n"))
			continue
		}
		_, _ = extra.Write([]byte(line[:at]))
		var output WinRMShellOutput
		err := json.Unmarshal([]byte(line[at+len(s.marker):]), &output)
		output.Output = string(extra.data) + output.Output
		extra.data = nil
		select {
		case s.replies <- shellReply{value: output, err: err}:
		case <-ctx.Done():
			return
		}
	}
	err := scanner.Err()
	if err == nil {
		select {
		case <-s.stderrDone:
		case <-ctx.Done():
		}
		err = fmt.Errorf("PowerShell-сессия завершилась")
		select {
		case <-s.stderrDone:
			if len(s.stderr.data) > 0 {
				err = fmt.Errorf("PowerShell-сессия завершилась: %s", strings.TrimSpace(string(s.stderr.data)))
			}
		default:
		}
	}
	select {
	case s.replies <- shellReply{err: err}:
	case <-ctx.Done():
	}
}

func (s *WinRMShell) Run(ctx context.Context, script string) (WinRMShellOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return WinRMShellOutput{}, err
	}
	request := base64.StdEncoding.EncodeToString([]byte(script)) + "\n"
	if _, err := io.WriteString(s.command.Stdin, request); err != nil {
		s.Close()
		return WinRMShellOutput{}, err
	}
	select {
	case reply, ok := <-s.replies:
		if !ok {
			s.Close()
			return WinRMShellOutput{}, fmt.Errorf("PowerShell-сессия закрыта")
		}
		if reply.err != nil {
			s.Close()
		}
		return reply.value, reply.err
	case <-ctx.Done():
		s.Close()
		return WinRMShellOutput{}, ctx.Err()
	}
}

func (s *WinRMShell) Close() {
	s.once.Do(func() {
		timer := time.AfterFunc(2*time.Second, s.cancel)
		go func() { defer s.cancel(); defer timer.Stop(); _ = s.command.Close(); _ = s.shell.Close() }()
	})
}

func (s *WinRMShell) CloseAndWait(ctx context.Context) {
	s.Close()
	select {
	case <-s.closed:
	case <-ctx.Done():
	}
}
