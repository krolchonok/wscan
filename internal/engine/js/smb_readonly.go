package js

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	smb2 "github.com/oiweiwei/go-smb2.fork"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
	"wscan/internal/domain"
)

type SMBBrowseOptions struct {
	EntryLimit int
	Host       string
	Port       int
	Mode       string
	Credential domain.Credential
}

func openSMBBrowse(ctx context.Context, o SMBBrowseOptions, timeout time.Duration) (*smb2.Session, net.Conn, error) {
	cred := o.Credential
	var initiator smb2.Initiator
	switch o.Mode {
	case "", "guest":
		initiator = &smb2.NTLMInitiator{User: "guest"}
	case "null":
		initiator = &smbNullInitiator{}
	case "credential":
		if cred.Username == "" && cred.Secret == "" && cred.Domain == "" && cred.Type == "password" {
			initiator = &smbNullInitiator{}
		} else {
			n := &smb2.NTLMInitiator{User: cred.Username, Domain: cred.Domain}
			if cred.Type == "ntlm-hash" {
				hash, err := hex.DecodeString(cred.Secret)
				if err != nil || len(hash) != 16 {
					return nil, nil, fmt.Errorf("SMB: NTLM-хеш должен содержать 16 байт")
				}
				n.Hash = hash
			} else if cred.Type == "password" {
				n.Password = cred.Secret
			} else {
				return nil, nil, fmt.Errorf("неподдерживаемый тип SMB-учётки")
			}
			initiator = n
		}
	default:
		return nil, nil, fmt.Errorf("SMB: неизвестный режим входа")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(o.Host, fmt.Sprint(o.Port)))
	if err != nil {
		return nil, nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	session, err := (&smb2.Dialer{Initiator: initiator}).DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return session.WithContext(ctx), conn, nil
}
func (c *SMBClient) ListSharesReadOnly(host string, port int, user, pass string) ([]SMBEntry, error) {
	return BrowseSMBWithOptions(c.ctx, SMBBrowseOptions{Host: host, Port: port, Mode: "credential", Credential: domain.Credential{Type: "password", Username: user, Secret: pass}}, "", "")
}
func (c *SMBClient) LoginUsingCredential(host string, port int, cred domain.Credential) (bool, error) {
	session, conn, err := openSMBBrowse(c.ctx, SMBBrowseOptions{Host: host, Port: port, Mode: "credential", Credential: cred}, c.timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	defer session.Logoff()
	return true, nil
}

type SMBConfigFinding struct {
	Path          string `json:"path"`
	SecretPresent *bool  `json:"secret_present"`
	Preview       string `json:"preview"`
}
type SMBConfigReport struct {
	Findings       []SMBConfigFinding `json:"findings"`
	EntriesVisited int                `json:"entries_visited"`
	Truncated      bool               `json:"truncated"`
	Errors         []string           `json:"errors,omitempty"`
}

var configSecretRE = regexp.MustCompile(`(?i)((?:password|pwd|secret|token|api[_-]?key)["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^;\r\n<]*)`)
var xmlSecretRE = regexp.MustCompile(`(?is)(<(?:password|pwd|secret|token)>)[^<]*(</(?:password|pwd|secret|token)>)`)

func MaskConfigSecrets(value string) string {
	value = configSecretRE.ReplaceAllString(value, "${1}[скрыто]")
	return xmlSecretRE.ReplaceAllString(value, "${1}[скрыто]${2}")
}
func secretPresence(recognized bool) *bool {
	if !recognized {
		return nil
	}
	yes := true
	return &yes
}
func FindSMBConfigs(ctx context.Context, o SMBBrowseOptions, share, root string) (*SMBConfigReport, error) {
	if share == "" || strings.EqualFold(share, "IPC$") {
		return nil, fmt.Errorf("выбери файловую шару для поиска")
	}
	o.EntryLimit = 201
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	report := &SMBConfigReport{Findings: []SMBConfigFinding{}}
	type node struct {
		path  string
		depth int
	}
	queue := []node{{root, 0}}
	for len(queue) > 0 && report.EntriesVisited < 200 && len(report.Findings) < 20 {
		current := queue[0]
		queue = queue[1:]
		entries, err := BrowseSMBWithOptions(ctx, o, share, current.path)
		if err != nil {
			report.Errors = append(report.Errors, current.path+": "+err.Error())
			if ctx.Err() != nil {
				return report, ctx.Err()
			}
			continue
		}
		for _, e := range entries {
			if e.ListingTruncated {
				report.Truncated = true
			}
			if report.EntriesVisited >= 200 {
				report.Truncated = true
				break
			}
			report.EntriesVisited++
			remote := path.Join(current.path, e.Name)
			if e.Directory {
				if current.depth < 3 {
					queue = append(queue, node{remote, current.depth + 1})
				} else {
					report.Truncated = true
				}
				continue
			}
			name := strings.ToLower(e.Name)
			wanted := strings.HasSuffix(name, ".dtsconfig") || name == "web.config" || name == "app.config" || name == ".env" || name == "config.ini" || strings.HasPrefix(name, "appsettings") && strings.HasSuffix(name, ".json")
			if !wanted {
				continue
			}
			if e.Size > 256*1024 {
				report.Errors = append(report.Errors, remote+": файл превышает 256 KiB")
				continue
			}
			var data bytes.Buffer
			_, err := ReadSMBFileWithOptions(ctx, o, share, remote, &data, 256*1024+1)
			if err != nil {
				report.Errors = append(report.Errors, remote+": "+err.Error())
				continue
			}
			if data.Len() > 256*1024 {
				report.Errors = append(report.Errors, remote+": файл превышает 256 KiB")
				continue
			}
			text := data.String()
			present := MaskConfigSecrets(text) != text
			// A small parser cannot safely redact every possible configuration format.
			// Ordinary results therefore never contain the original configuration body.
			preview := "Конфигурационный файл доступен"
			if present {
				preview += "; значение секрета: [скрыто]"
			}
			report.Findings = append(report.Findings, SMBConfigFinding{remote, secretPresence(present), preview})
			if len(report.Findings) >= 20 {
				report.Truncated = true
				break
			}
		}
	}
	if len(queue) > 0 {
		report.Truncated = true
	}
	return report, nil
}

func readSMBDirectory(share *smb2.Share, remote string, limit int) ([]os.FileInfo, bool, error) {
	directory, err := share.Open(remote)
	if err != nil {
		return nil, false, err
	}
	defer directory.Close()
	entries, err := directory.Readdir(limit + 1)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	truncated := len(entries) > limit
	if truncated {
		entries = entries[:limit]
	}
	return entries, truncated, nil
}
func probeSMBReadAccess(share *smb2.Share) (*bool, *bool, string) {
	_, _, err := readSMBDirectory(share, ".", 1)
	read := smbAccessResult(err)
	if err != nil && read == nil {
		return nil, nil, err.Error()
	}
	return read, nil, ""
}
