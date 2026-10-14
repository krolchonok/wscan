package js

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/masterzen/winrm"
	"wscan/internal/domain"
)

// WinRMOptions represents one explicit connection with a saved password.
type WinRMOptions struct {
	Host             string
	Port             int
	HTTPS            bool
	Insecure         bool
	Credential       domain.Credential
	Timeout          time.Duration
	transportFactory func(func(string, string) (net.Conn, error)) winrm.Transporter
}

type WinRMFile struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Directory   bool   `json:"directory"`
	Size        int64  `json:"size"`
	Modified    string `json:"modified"`
	Owner       string `json:"owner"`
	Rights      string `json:"rights"`
	AccessError string `json:"access_error"`
}

type WinRMDirectory struct {
	Path      string      `json:"path"`
	Parent    string      `json:"parent"`
	Entries   []WinRMFile `json:"entries"`
	Truncated bool        `json:"truncated"`
}

func psLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

type winRMConn struct {
	net.Conn
	stop func() bool
}

func (c *winRMConn) Close() error { c.stop(); return c.Conn.Close() }

func newInteractionWinRM(ctx context.Context, o WinRMOptions) (*winrm.Client, error) {
	if o.Credential.Type != "password" {
		return nil, fmt.Errorf("WinRM: сейчас поддерживается учётка с паролем")
	}
	if o.Host == "" || o.Port < 1 || o.Port > 65535 || o.Credential.Username == "" {
		return nil, fmt.Errorf("WinRM: нужны хост, порт и имя пользователя")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	endpoint := winrm.NewEndpoint(o.Host, o.Port, o.HTTPS, o.Insecure, nil, nil, nil, timeout)
	params := *winrm.DefaultParameters
	factory := o.transportFactory
	if factory == nil {
		factory = func(dial func(string, string) (net.Conn, error)) winrm.Transporter {
			return winrm.NewClientNTLMWithDial(dial)
		}
	}
	params.TransportDecorator = func() winrm.Transporter {
		return factory(func(network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			return &winRMConn{Conn: conn, stop: stop}, nil
		})
	}

	return winrm.NewClientWithParameters(endpoint, identity(o.Credential.Domain, o.Credential.Username), o.Credential.Secret, &params)
}

// cappedOutput drains the command even when its output exceeds the UI limit.
// Stopping the read early would block WinRM's stdout/stderr pipes.
type cappedOutput struct {
	data      []byte
	limit     int
	truncated bool
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	room := w.limit - len(w.data)
	if room < n {
		w.truncated = true
	}
	if room > 0 {
		w.data = append(w.data, p[:min(room, n)]...)
	}
	return n, nil
}

func RunWinRMPowerShell(ctx context.Context, o WinRMOptions, script string, limit int) (string, string, int, error) {
	client, err := newInteractionWinRM(ctx, o)
	if err != nil {
		return "", "", 0, err
	}
	if limit <= 0 {
		limit = 1024 * 1024
	}
	out, stderr := &cappedOutput{limit: limit}, &cappedOutput{limit: 64 * 1024}
	prologue := "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding; $ErrorActionPreference='Stop'; "
	command := winrm.Powershell(prologue + script)
	var input io.Reader
	if len(command) > 7000 {
		// Some WinRS/PowerShell combinations never deliver stdin EOF to
		// Console.In.ReadToEnd. Prefer a compressed, self-contained command.
		var compressed bytes.Buffer
		packed := gzip.NewWriter(&compressed)
		if _, err := io.WriteString(packed, script); err != nil {
			return "", "", 0, err
		}
		if err := packed.Close(); err != nil {
			return "", "", 0, err
		}
		payload := base64.StdEncoding.EncodeToString(compressed.Bytes())
		unpack := "$__wscan_gz='" + payload + "';$__wm=New-Object IO.MemoryStream(,[Convert]::FromBase64String($__wscan_gz));$__wg=New-Object IO.Compression.GZipStream($__wm,[IO.Compression.CompressionMode]::Decompress);$__wr=New-Object IO.StreamReader($__wg,[Text.Encoding]::UTF8);try{Invoke-Expression ($__wr.ReadToEnd())}finally{$__wr.Dispose();$__wg.Dispose();$__wm.Dispose()}"
		compressedCommand := winrm.Powershell(prologue + unpack)
		if len(compressedCommand) <= 8000 {
			command = compressedCommand
		} else {
			// cmd.exe on old Windows limits command lines to 8191 characters.
			command = winrm.Powershell(prologue + "[Console]::InputEncoding = New-Object System.Text.UTF8Encoding; Invoke-Expression ([Console]::In.ReadToEnd())")
			input = strings.NewReader(script)
		}
	}
	code, err := client.RunWithContextWithInput(ctx, command, out, stderr, input)
	text := string(out.data)
	if out.truncated {
		text += "\n[Вывод обрезан]"
	}
	return text, string(stderr.data), code, err
}

func winRMScript(ctx context.Context, o WinRMOptions, script string) (string, error) {
	out, stderr, code, err := RunWinRMPowerShell(ctx, o, script, 2*1024*1024)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("WinRM: код %d: %s", code, strings.TrimSpace(stderr))
	}
	return strings.TrimSpace(strings.TrimPrefix(out, "\ufeff")), nil
}

func WinRMIdentity(ctx context.Context, o WinRMOptions) (string, error) {
	return winRMScript(ctx, o, `whoami; hostname; whoami /groups; whoami /priv`)
}

func BrowseWinRM(ctx context.Context, o WinRMOptions, remote string) (WinRMDirectory, error) {
	script := `$p=` + psLiteral(remote) + `; if (-not $p) {$p=$env:USERPROFILE}; $root=Get-Item -LiteralPath $p -Force; if (-not $root.PSIsContainer) {throw 'Выбери каталог'};
 $items=@(Get-ChildItem -LiteralPath $root.FullName -Force | Sort-Object @{Expression={$_.PSIsContainer};Descending=$true},Name | Select-Object -First 1001);
 $truncated=$items.Count -gt 1000; $entries=@($items | Select-Object -First 1000 | ForEach-Object {
 $item=$_;$owner='';$rights='';$accessError='';try {$acl=Get-Acl -LiteralPath $item.FullName;$owner=$acl.Owner;$rights=($acl.Access | ForEach-Object {"$($_.IdentityReference): $($_.FileSystemRights) [$($_.AccessControlType)]"}) -join '; '}catch {$accessError=$_.Exception.Message};
 [pscustomobject]@{name=$item.Name;path=$item.FullName;directory=[bool]$item.PSIsContainer;size= $(if ($item.PSIsContainer) {0} else {$item.Length});modified=$item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss');owner=$owner;rights=$rights;access_error=$accessError}
 }); $parent='';if($root.Parent){$parent=$root.Parent.FullName}; [pscustomobject]@{path=$root.FullName;parent=$parent;entries=$entries;truncated=$truncated} | ConvertTo-Json -Depth 5 -Compress`
	out, err := winRMScript(ctx, o, script)
	if err != nil {
		return WinRMDirectory{}, err
	}
	var result WinRMDirectory
	err = json.Unmarshal([]byte(out), &result)
	if err != nil {
		return result, fmt.Errorf("WinRM: не удалось разобрать список файлов: %w", err)
	}
	return result, nil
}

// ReadWinRMFile transfers bounded chunks, so a large file never fills RAM.
func ReadWinRMFile(ctx context.Context, o WinRMOptions, remote string, dst io.Writer, limit int64) (int64, error) {
	var offset int64
	for {
		if err := ctx.Err(); err != nil {
			return offset, err
		}
		count := int64(24 * 1024)
		if limit > 0 {
			if limit-offset < count {
				count = limit - offset
			}
			if count <= 0 {
				return offset, nil
			}
		}
		script := fmt.Sprintf(`$f=[System.IO.File]::Open(%s,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite);try{$null=$f.Seek(%d,[System.IO.SeekOrigin]::Begin);$b=New-Object byte[] %d;$n=$f.Read($b,0,$b.Length);[Convert]::ToBase64String($b,0,$n)}finally{$f.Dispose()}`, psLiteral(remote), offset, count)
		encoded, err := winRMScript(ctx, o, script)
		if err != nil {
			return offset, err
		}
		chunk, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return offset, fmt.Errorf("WinRM: повреждённый блок файла: %w", err)
		}
		if int64(len(chunk)) > count {
			return offset, fmt.Errorf("WinRM: размер блока превышает запрошенный")
		}
		n, err := dst.Write(chunk)
		offset += int64(n)
		if err != nil {
			return offset, err
		}
		if n != len(chunk) {
			return offset, io.ErrShortWrite
		}
		if int64(len(chunk)) < count {
			return offset, nil
		}
	}
}

func DownloadWinRM(ctx context.Context, o WinRMOptions, remote, directory string) (string, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	name := filepath.Base(strings.ReplaceAll(remote, `\`, "/"))
	if name == "." || name == "/" || name == "" {
		return "", fmt.Errorf("выбери файл")
	}
	file, err := os.CreateTemp(directory, "winrm-*-"+strings.ReplaceAll(name, "*", "_"))
	if err != nil {
		return "", err
	}
	_, err = ReadWinRMFile(ctx, o, remote, file, 0)
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}
