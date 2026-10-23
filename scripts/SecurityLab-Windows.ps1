# SecurityLab Toolkit - Windows audit and opt-in hardening
$ErrorActionPreference = 'Continue'
$ReportDir = Join-Path $HOME 'SecurityLab-Reports'
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
function Invoke-Audit {
  Write-Output '=== System ==='
  Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber
  Write-Output '=== Local accounts ==='
  Get-LocalUser | Select-Object Name,Enabled,LastLogon
  Write-Output '=== Administrators ==='
  try { Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name,ObjectClass } catch { Write-Warning $_ }
  Write-Output '=== Firewall ==='
  Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
  Write-Output '=== Listening TCP ports ==='
  Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess
  Write-Output '=== Defender ==='
  if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated }
  Write-Output '=== Critical services ==='
  Get-Service -Name wuauserv,WinDefend,MpsSvc -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
}
function Save-Report {
  $Path = Join-Path $ReportDir ("audit-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
  Invoke-Audit | Out-String -Width 240 | Set-Content -Path $Path -Encoding UTF8
  Write-Host "Report saved: $Path"
}
function Enable-Firewall {
  Write-Warning 'Changing firewall settings may interrupt remote access.'
  $Answer = Read-Host 'Type YES to enable all firewall profiles'
  if ($Answer -cne 'YES') { Write-Host 'Cancelled'; return }
  $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $IsAdmin) { Write-Warning 'Run PowerShell as Administrator'; return }
  Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
}
while ($true) {
  Write-Host "`nSecurityLab Windows | 1 Audit | 2 Save report | 3 Enable firewall (confirm) | 4 Exit"
  $Choice = Read-Host 'Select'
  switch ($Choice) {
    '1' { Invoke-Audit | Format-Table -AutoSize | Out-Host }
    '2' { Save-Report }
    '3' { Enable-Firewall }
    '4' { return }
    default { Write-Host 'Invalid option' }
  }
}
