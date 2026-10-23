# SecurityLab Toolkit — Windows Server audit
# PowerShell 5.1+, authorized systems only
$ErrorActionPreference='Continue'
function Audit {
  Write-Output '=== Windows Server system ==='
  Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber
  Write-Output '=== Accounts ==='
  Get-LocalUser | Select-Object Name,Enabled,LastLogon
  Write-Output '=== Administrators ==='
  Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Continue | Select-Object Name,ObjectClass
  Write-Output '=== Firewall ==='
  Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction
  Write-Output '=== Listening ports ==='
  Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess
  Write-Output '=== Defender ==='
  if(Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue){Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated}
  Write-Output '=== Server services ==='
  Get-Service -Name LanmanServer,TermService,WinRM,wuauserv -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
  Write-Output '=== Recent updates ==='
  Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
}
function SaveReport {
  $folder=Join-Path $HOME 'SecurityLab-Reports'
  New-Item -ItemType Directory -Path $folder -Force | Out-Null
  $path=Join-Path $folder ("winserver-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
  Audit | Out-String -Width 220 | Set-Content -Encoding UTF8 -Path $path
  Write-Host "Saved: $path"
}
while($true){
 Write-Host "`nWindows Server | 1 Audit | 2 Save report | 3 Exit"
 $choice=Read-Host 'Select'
 switch($choice){'1'{Audit | Out-Host};'2'{SaveReport};'3'{return};default{Write-Host 'Invalid option'}}
}
