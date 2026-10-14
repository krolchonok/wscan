package js

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"wscan/internal/domain"
)

type WindowsAuditSection struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}
type WindowsAuditCheck struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
}
type WindowsAudit struct {
	Host     string                         `json:"host"`
	Sections map[string]WindowsAuditSection `json:"sections"`
	Policy   *domain.PasswordPolicy         `json:"password_policy,omitempty"`
	Checks   []WindowsAuditCheck            `json:"checks"`
}

// AuthenticatedAuditError distinguishes a failed query/decoder from a failed login.
type AuthenticatedAuditError struct{ Err error }

func (e *AuthenticatedAuditError) Error() string { return e.Err.Error() }
func (e *AuthenticatedAuditError) Unwrap() error { return e.Err }

// One bounded, read-only inventory request. Each subsection reports its own
// access error; missing data never means that a security control is enabled.
// NetUserModalsGet reads the local SAM policy without exporting security files.
const windowsAuditScript = `
if (-not (Get-Command ConvertTo-Json -ErrorAction SilentlyContinue)) { throw 'Windows audit requires PowerShell 3.0 or later for JSON output' }
$result = @{}
function Read-Section($name, [scriptblock]$code) {
 try {
  if (@('patches','network','interfaces','routes','firewall','dns_zones') -contains $name) { $result[$name] = @{data = @(& $code)} }
  else { $result[$name] = @{data = (& $code)} }
 } catch { $result[$name] = @{error = $_.Exception.Message} }
}
Read-Section 'os' {
 $o = Get-WmiObject Win32_OperatingSystem
 @{caption=$o.Caption;version=$o.Version;build=$o.BuildNumber;service_pack=$o.CSDVersion}
}
Read-Section 'computer' {
 $c = Get-WmiObject Win32_ComputerSystem
 @{name=$c.Name;domain=$c.Domain;part_of_domain=$c.PartOfDomain;domain_role=[int]$c.DomainRole}
}
Read-Section 'wdigest' {
 $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest')
 if ($null -eq $key) { @{present=$false} } else {
  try { $v = $key.GetValue('UseLogonCredential',$null); @{present=($null -ne $v);value=$v} } finally { $key.Close() }
 }
}
Read-Section 'patches' { @(Get-WmiObject Win32_QuickFixEngineering | ForEach-Object { @{id=$_.HotFixID;installed_on=[string]$_.InstalledOn} }) }
Read-Section 'network' { @(Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
 @{description=$_.Description;index=$_.Index;ip=@($_.IPAddress);subnet=@($_.IPSubnet);gateway=@($_.DefaultIPGateway);dns=@($_.DNSServerSearchOrder);dhcp=$_.DHCPEnabled}
}) }
Read-Section 'interfaces' { @(Get-WmiObject Win32_NetworkAdapter | Where-Object { $null -ne $_.NetConnectionID } | ForEach-Object { @{index=$_.Index;name=$_.NetConnectionID;description=$_.Name;enabled=$_.NetEnabled} }) }
Read-Section 'routes' { @(Get-WmiObject Win32_IP4RouteTable | ForEach-Object { @{destination=$_.Destination;mask=$_.Mask;next_hop=$_.NextHop;interface_index=$_.InterfaceIndex;metric=$_.Metric1} }) }
Read-Section 'firewall' {
 $f = New-Object -ComObject HNetCfg.FwPolicy2
 @(1,2,4 | ForEach-Object { @{profile=$_;enabled=$f.FirewallEnabled($_);default_inbound=$f.DefaultInboundAction($_);default_outbound=$f.DefaultOutboundAction($_)} })
}
Read-Section 'dns_zones' { @(Get-WmiObject -Namespace 'root\MicrosoftDNS' -Class MicrosoftDNS_Zone | ForEach-Object {
 @{name=$_.Name;allow_update=$_.AllowUpdate;secure_secondaries=$_.SecureSecondaries;secondaries=@($_.SecondaryServers);notify=@($_.NotifyServers)}
}) }
Read-Section 'local_policy' {
 if (-not ('WScanPolicyReader' -as [type])) {
 Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public static class WScanPolicyReader {
 [DllImport("Netapi32.dll", CharSet=CharSet.Unicode)] static extern int NetUserModalsGet(string server, int level, out IntPtr buffer);
 [DllImport("Netapi32.dll")] static extern int NetApiBufferFree(IntPtr buffer);
 [StructLayout(LayoutKind.Sequential)] struct Policy {public uint min;public uint maxAge;public uint minAge;public uint logoff;public uint history;}
 [StructLayout(LayoutKind.Sequential)] struct Lockout {public uint duration;public uint window;public uint threshold;}
 public static Dictionary<string,object> Read() {
  var d=new Dictionary<string,object>();IntPtr p;
  int e=NetUserModalsGet(null,0,out p);if(e!=0)throw new Exception("NetUserModalsGet(0): "+e);
  try {var a=(Policy)Marshal.PtrToStructure(p,typeof(Policy));d["min_length"]=a.min;d["history_length"]=a.history;d["min_age_seconds"]=a.minAge;d["max_age_seconds"]=a.maxAge==UInt32.MaxValue ? 0 : a.maxAge;}finally{NetApiBufferFree(p);}
  e=NetUserModalsGet(null,3,out p);if(e!=0)throw new Exception("NetUserModalsGet(3): "+e);
  try {var a=(Lockout)Marshal.PtrToStructure(p,typeof(Lockout));d["lockout_threshold"]=a.threshold;d["lockout_duration_seconds"]=a.duration;d["observation_window_seconds"]=a.window;}finally{NetApiBufferFree(p);}
  return d;
 }
}
'@
 }
 [WScanPolicyReader]::Read()
}
ConvertTo-Json -InputObject $result -Depth 8 -Compress
`

func CollectWindowsAudit(ctx context.Context, o WinRMOptions) (WindowsAudit, error) {
	r := WindowsAudit{Host: o.Host}
	out, stderr, code, e := RunWinRMPowerShell(ctx, o, windowsAuditScript, 1024*1024)
	if e != nil {
		return r, e
	}
	if code != 0 {
		return r, &AuthenticatedAuditError{fmt.Errorf("Windows audit exit %d: %s", code, strings.TrimSpace(stderr))}
	}
	r, e = parseWindowsAudit(o.Host, out)
	if e != nil {
		return r, &AuthenticatedAuditError{e}
	}
	return r, nil
}

func parseWindowsAudit(host, output string) (WindowsAudit, error) {
	r := WindowsAudit{Host: host}
	if e := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(output), "\ufeff")), &r.Sections); e != nil {
		return r, fmt.Errorf("неполный JSON Windows-аудита: %w", e)
	}
	add := func(id, state, severity, evidence string) {
		r.Checks = append(r.Checks, WindowsAuditCheck{id, state, severity, evidence})
	}
	for _, name := range []string{"os", "computer", "wdigest", "patches", "network", "interfaces", "routes", "firewall", "dns_zones", "local_policy"} {
		section, ok := r.Sections[name]
		if section.Error != "" {
			state := "error"
			if strings.Contains(strings.ToLower(section.Error), "denied") || strings.Contains(section.Error, "0x80070005") {
				state = "denied"
			}
			add(name, state, "info", section.Error)
			continue
		}
		if !ok || len(section.Data) == 0 || string(section.Data) == "null" {
			add(name, "incomplete", "info", "Раздел не возвращён; "+section.Error)
			continue
		}
		add(name, "observed", "info", string(section.Data))
	}
	var computer struct {
		PartOfDomain *bool `json:"part_of_domain"`
		DomainRole   *int  `json:"domain_role"`
	}
	_ = json.Unmarshal(r.Sections["computer"].Data, &computer)
	if computer.PartOfDomain != nil && !*computer.PartOfDomain {
		add("domain-join", "confirmed", "info", "Машина сообщает PartOfDomain=false; необходимость domain join зависит от её роли")
	}
	var osInfo struct {
		Version string `json:"version"`
		Caption string `json:"caption"`
	}
	_ = json.Unmarshal(r.Sections["os"].Data, &osInfo)
	var wd struct {
		Present *bool  `json:"present"`
		Value   *int64 `json:"value"`
	}
	if json.Unmarshal(r.Sections["wdigest"].Data, &wd) == nil {
		switch {
		case wd.Present != nil && *wd.Present && wd.Value != nil && *wd.Value == 1:
			add("wdigest-storage", "confirmed", "high", "UseLogonCredential=1; наличие конкретных паролей в LSASS не проверялось")
		case wd.Present != nil && *wd.Present && wd.Value != nil && *wd.Value == 0:
			add("wdigest-storage", "negative", "info", "UseLogonCredential=0; поддержка настройки зависит от обновлений старых Windows")
		case wd.Present != nil && !*wd.Present:
			parts := strings.Split(osInfo.Version, ".")
			major, minor := 0, 0
			if len(parts) >= 2 {
				major, _ = strconv.Atoi(parts[0])
				minor, _ = strconv.Atoi(parts[1])
			}
			if major > 6 || major == 6 && minor >= 3 {
				add("wdigest-storage", "negative", "info", "Параметр отсутствует; указанная версия Windows отключает кэширование WDigest по умолчанию")
			} else if major > 0 {
				add("wdigest-storage", "candidate", "high", "Параметр отсутствует на старой Windows; отключение WDigest не подтверждено")
			} else {
				add("wdigest-storage", "incomplete", "info", "Параметр отсутствует, версия ОС неизвестна")
			}
		default:
			add("wdigest-storage", "incomplete", "info", "Неподдерживаемое значение UseLogonCredential")
		}
	}
	var fw []struct {
		Profile  int   `json:"profile"`
		Enabled  *bool `json:"enabled"`
		Outbound int   `json:"default_outbound"`
	}
	if json.Unmarshal(r.Sections["firewall"].Data, &fw) == nil {
		for _, f := range fw {
			if f.Enabled != nil && !*f.Enabled {
				add(fmt.Sprintf("firewall-disabled/%d", f.Profile), "confirmed", "medium", "Профиль Windows Firewall отключён; действующее сетевое ограничение не оценено")
			}
		}
	}
	var zones []struct {
		Name        string `json:"name"`
		AllowUpdate *int   `json:"allow_update"`
	}
	if json.Unmarshal(r.Sections["dns_zones"].Data, &zones) == nil {
		for _, z := range zones {
			if z.AllowUpdate != nil && *z.AllowUpdate == 1 {
				add("dns-insecure-update/"+z.Name, "confirmed", "high", "DNS-зона разрешает небезопасные динамические обновления; записи не изменялись")
			}
		}
	}
	if data := r.Sections["local_policy"]; data.Error == "" && len(data.Data) > 0 && string(data.Data) != "null" {
		var p domain.PasswordPolicy
		if e := json.Unmarshal(data.Data, &p); e == nil {
			p.Source = "local"
			p.DN = host
			p.MissingFields = []string{"complexity", "reversible_encryption"}
			if computer.DomainRole == nil {
				p.Source = "unknown"
			} else if *computer.DomainRole >= 4 {
				p.Source = "domain"
			}
			r.Policy = &p
		}
	}
	// QFE is inventory, not a patch applicability/supersedence engine.
	add("patch-coverage", "incomplete", "info", "QFE сохранён; отсутствие конкретного KB не доказывает отсутствие исправления. Сетевые MS17-010/BlueKeep выполняются отдельными проверками.")
	return r, nil
}
