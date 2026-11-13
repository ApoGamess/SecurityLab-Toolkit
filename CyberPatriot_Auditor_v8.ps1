# CyberPatriot Auditor v8 - Windows PowerShell 5.1
# Run as administrator in an authorized training VM. Review scenario instructions first.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$script:Admins=@('chowe','josiah','isabella','rafael')
$script:Users=@('hayes','nia','simone','foster','tina','edwards','darius','peterson','turner','ethan','esther','wyatt')
$script:Findings=New-Object System.Collections.ArrayList
$script:Log=New-Object System.Collections.ArrayList
$script:Language='es'
$script:LastRepair=@()
function Add-Finding($category,$item,$detail,$fix,$target) {
 [void]$script:Findings.Add([pscustomobject]@{Category=$category;Item=$item;Detail=$detail;Fix=$fix;Target=$target;Result='Pending'})
}
function Is-Admin {
 $p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
 return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Scan-System {
 $script:Findings.Clear()
 try {
  $protected=@($script:Admins)+@($script:Users)+@('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')
  foreach($u in @(Get-LocalUser -ErrorAction Stop)) {
   if($u.Enabled -and $u.Name -notin $protected) {Add-Finding 'Accounts' $u.Name 'Unknown enabled local account: review scenario' 'Review' $u.Name}
   if($u.Name -in $script:Users -and -not $u.PasswordRequired) {Add-Finding 'Accounts' $u.Name 'Password not required' 'Review' $u.Name}
  }
  $members=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
  foreach($m in $members) {
   $n=($m.Name -split '\\')[-1]
   if($m.ObjectClass -eq 'User' -and $n -in $script:Users) {Add-Finding 'Accounts' $n 'Standard user belongs to Administrators' 'Demote' $n}
  }
  foreach($n in $script:Admins) {
   if((Get-LocalUser -Name $n -ErrorAction SilentlyContinue) -and $n -notin @($members | ForEach-Object {($_.Name -split '\\')[-1]})) {
    Add-Finding 'Accounts' $n 'Authorized administrator lacks membership' 'Promote' $n
   }
  }
  foreach($n in $script:Users){if(-not (Get-LocalUser -Name $n -ErrorAction SilentlyContinue)){Add-Finding 'Accounts' $n 'Expected user missing; manual verification' 'Review' $n}}
 }catch{Add-Finding 'Error' 'Local accounts' $_.Exception.Message 'Review' ''}
 try {foreach($f in @(Get-NetFirewallProfile -ErrorAction Stop)){if(-not $f.Enabled){Add-Finding 'Firewall' $f.Name 'Firewall disabled' 'Firewall' $f.Name}}}catch{Add-Finding 'Error' 'Firewall' $_.Exception.Message 'Review' ''}
 foreach($name in @('RemoteRegistry','simptcp')) {
  try {$s=Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
   if($s -and ($s.State -eq 'Running' -or $s.StartMode -ne 'Disabled')) {Add-Finding 'Services' $name "State=$($s.State); Start=$($s.StartMode)" 'Service' $name}
  }catch{}
 }
 try {$rdp=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections
  if($rdp -eq 0){Add-Finding 'Remote access' 'RDP' 'Remote Desktop enabled; verify scenario requirements' 'Review' 'RDP'}
 }catch{}
 try {$d=Get-MpComputerStatus -ErrorAction Stop;if(-not $d.RealTimeProtectionEnabled){Add-Finding 'Defender' 'Real-time protection' 'Disabled or not reported' 'Review' ''}}catch{}
 try {$s=Get-SmbShare -ErrorAction Stop;foreach($share in $s){if($share.Name -notin @('ADMIN$','C$','IPC$','print$')){Add-Finding 'Shares' $share.Name 'Non-default share; verify authorization' 'Review' $share.Name}}}catch{}
 try {$p=Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {$_.OwningProcess -eq 4};foreach($port in @($p|Select-Object -ExpandProperty LocalPort -Unique)){[void]$script:Log.Add("System PID 4 TCP listening: $port")}}catch{}
 try {$pol=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue;if($pol -and $pol.NoAutoUpdate -eq 1){Add-Finding 'Updates' 'Automatic updates' 'Disabled by policy' 'Updates' ''}}catch{}
 try {$reg=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop;if($reg.dontdisplaylastusername -ne 1){Add-Finding 'Sign-in' 'Last username' 'Last username shown at logon' 'HideLast' ''}}catch{}
 try {
  $polPath=Join-Path $env:TEMP ('cp_audit_'+[guid]::NewGuid().ToString('N')+'.inf')
  & secedit.exe /export /cfg $polPath /areas SECURITYPOLICY 2>$null | Out-Null
  if(Test-Path -LiteralPath $polPath){
   $polText=Get-Content -LiteralPath $polPath -Raw
   Remove-Item -LiteralPath $polPath -Force -ErrorAction SilentlyContinue
   if($polText -match '(?m)^\s*PasswordComplexity\s*=\s*0\s*$'){Add-Finding 'Policy' 'Password complexity' 'Password complexity disabled' 'Review' ''}
   if($polText -match '(?m)^\s*MinimumPasswordLength\s*=\s*(\d+)'){if([int]$Matches[1] -lt 8){Add-Finding 'Policy' 'Minimum password length' 'Below 8 characters; verify scenario target' 'Review' ''}}
   if($polText -match '(?m)^\s*PasswordHistorySize\s*=\s*(\d+)'){if([int]$Matches[1] -lt 5){Add-Finding 'Policy' 'Password history' 'Below 5 remembered passwords; verify scenario target' 'Review' ''}}
  }
 }catch{Add-Finding 'Error' 'Security policy' $_.Exception.Message 'Review' ''}
 try {
  $svc=Get-Service -Name 'wuauserv' -ErrorAction Stop
  if($svc.StartType -eq 'Disabled'){Add-Finding 'Updates' 'Windows Update service' 'Service disabled' 'Review' ''}
 }catch{Add-Finding 'Error' 'Windows Update service' $_.Exception.Message 'Review' ''}
 try {
  $sm=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue
  if($sm -and $sm.EnableSmartScreen -eq 0){Add-Finding 'Security' 'SmartScreen' 'Disabled by policy' 'Review' ''}
 }catch{}
 try {
  $uac=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
  if($uac.EnableLUA -eq 0){Add-Finding 'Security' 'UAC' 'User Account Control disabled' 'Review' ''}
 }catch{}
 try {
  $appPaths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
  foreach($app in @(Get-ItemProperty $appPaths -ErrorAction SilentlyContinue)){
   if($app.DisplayName -match 'WildTangent|Wireshark|WinDirStat|CCleaner'){
    Add-Finding 'Software' $app.DisplayName 'Installed application; determine if permitted in scenario' 'Review' ''
   }
  }
 }catch{}
 try {
  $files=@(Get-ChildItem -LiteralPath 'C:\Users\Public\Music' -Filter '*.mp3' -File -ErrorAction SilentlyContinue)
  if($files.Count -gt 0){Add-Finding 'Files' 'Public MP3' "$($files.Count) MP3 file(s) found; review before removal" 'Review' ''}
 }catch{}
 if($script:Findings.Count -eq 0){Add-Finding 'Summary' 'No detected issues' 'Only implemented checks were evaluated' 'Review' ''}
}
function Repair-Finding($f) {
 try {
  switch($f.Fix) {
   'Firewall' {Set-NetFirewallProfile -Name $f.Target -Enabled True -ErrorAction Stop;break}
   'Service' {Stop-Service -Name $f.Target -Force -ErrorAction SilentlyContinue;Set-Service -Name $f.Target -StartupType Disabled -ErrorAction Stop;break}
   'Demote' {Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $f.Target -ErrorAction Stop;break}
   'Promote' {Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $f.Target -ErrorAction Stop;break}
   'Updates' {Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0 -ErrorAction Stop;break}
   'HideLast' {Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name dontdisplaylastusername -Value 1 -ErrorAction Stop;break}
   default {$f.Result='Manual review';return}
  }
  $f.Result='Attempted - verifying'
 }catch{$f.Result='Failed: '+$_.Exception.Message}
 [void]$script:Log.Add("$($f.Category) / $($f.Item): $($f.Result)")
}
function Cipher([string]$inputText,[string]$kind,[int]$shift) {
 $sb=New-Object System.Text.StringBuilder
 foreach($c in $inputText.ToCharArray()) {
  $n=[int][char]$c
  if(($n -ge 65 -and $n -le 90) -or ($n -ge 97 -and $n -le 122)) {
   $base=if($n -le 90){65}else{97};$i=$n-$base
   $v=if($kind -eq 'Atbash'){25-$i}else{($i+$shift)%26}
   [void]$sb.Append([char]($base+$v))
  }else{[void]$sb.Append($c)}
 }
 return $sb.ToString()
}
$form=New-Object Windows.Forms.Form
$form.Text='CyberPatriot Auditor v8 | Windows 11'
$form.Size=New-Object Drawing.Size(1150,760)
$form.MinimumSize=New-Object Drawing.Size(880,600)
$form.StartPosition='CenterScreen'
$tabs=New-Object Windows.Forms.TabControl
$tabs.Dock='Fill';$form.Controls.Add($tabs)
$tabAudit=New-Object Windows.Forms.TabPage('Audit / Auditoria');$tabAccounts=New-Object Windows.Forms.TabPage('Accounts / Cuentas')
$tabCipher=New-Object Windows.Forms.TabPage('Ciphers / Cifrados');$tabSettings=New-Object Windows.Forms.TabPage('Settings / Configuracion')
$tabs.TabPages.AddRange(@($tabAudit,$tabAccounts,$tabCipher,$tabSettings))
$top=New-Object Windows.Forms.FlowLayoutPanel;$top.Dock='Top';$top.Height=55;$tabAudit.Controls.Add($top)
$scanBtn=New-Object Windows.Forms.Button;$scanBtn.Text='SCAN / VERIFICAR';$scanBtn.Width=170;$scanBtn.Height=40;$top.Controls.Add($scanBtn)
$fixBtn=New-Object Windows.Forms.Button;$fixBtn.Text='FIX ALL / REPARAR TODO';$fixBtn.Width=220;$fixBtn.Height=40;$top.Controls.Add($fixBtn)
$exportBtn=New-Object Windows.Forms.Button;$exportBtn.Text='EXPORT REPORT';$exportBtn.Width=150;$exportBtn.Height=40;$top.Controls.Add($exportBtn)
$grid=New-Object Windows.Forms.DataGridView;$grid.Dock='Fill';$grid.ReadOnly=$true;$grid.AutoSizeColumnsMode='Fill';$grid.AllowUserToAddRows=$false;$grid.RowHeadersVisible=$false;$tabAudit.Controls.Add($grid);$grid.BringToFront();$top.BringToFront()
$status=New-Object Windows.Forms.Label;$status.Dock='Bottom';$status.Height=36;$status.Text='Ready. Scan does not modify the computer.';$tabAudit.Controls.Add($status)
$logBox=New-Object Windows.Forms.TextBox;$logBox.Dock='Bottom';$logBox.Height=110;$logBox.Multiline=$true;$logBox.ScrollBars='Vertical';$logBox.ReadOnly=$true;$tabAudit.Controls.Add($logBox)
function Refresh-Grid {$grid.DataSource=$null;$grid.DataSource=@($script:Findings);$logBox.Text=$script:Log -join [Environment]::NewLine}
$scanBtn.Add_Click({Scan-System;Refresh-Grid;$status.Text=if($script:Language -eq 'es'){"Se encontraron $($script:Findings.Count) hallazgos. Revisa el escenario."}else{"Found $($script:Findings.Count) findings. Review the scenario."}})
$fixBtn.Add_Click({
 if(-not(Is-Admin)){[Windows.Forms.MessageBox]::Show('Run PowerShell as Administrator.');return}
 $n=@($script:Findings|Where-Object {$_.Fix -ne 'Review'}).Count
 if($n -eq 0){[Windows.Forms.MessageBox]::Show('Scan first; no implemented fixes pending.');return}
 $prompt=if($script:Language -eq 'es'){"¿Intentar $n reparaciones? Se modificarán cuentas o ajustes del sistema. Confirma las reglas del escenario."}else{"Attempt $n repairs? Accounts and system settings may change. Check scenario rules."};$answer=[Windows.Forms.MessageBox]::Show($prompt,'FIX ALL / REPARAR TODO','YesNo','Warning')
 if($answer -ne 'Yes'){return}
 foreach($f in $script:Findings){if($f.Fix -ne 'Review'){Repair-Finding $f}}
 $before=@($script:Log);Scan-System;$script:Log=New-Object System.Collections.ArrayList;foreach($line in $before){[void]$script:Log.Add($line)}
 Refresh-Grid;$status.Text=if($script:Language -eq 'es'){'Reparaciones intentadas. Equipo verificado nuevamente; se muestran pendientes.'}else{'Repairs attempted. System rescanned; remaining issues shown.'}
})
$exportBtn.Add_Click({
 $dialog=New-Object Windows.Forms.SaveFileDialog;$dialog.Filter='CSV (*.csv)|*.csv';$dialog.FileName='CyberPatriot_v8_report.csv'
 if($dialog.ShowDialog() -eq 'OK'){$script:Findings|Export-Csv -NoTypeInformation -Encoding UTF8 -Path $dialog.FileName}
})
$accountHelp=New-Object Windows.Forms.Label;$accountHelp.Dock='Top';$accountHelp.Height=55;$accountHelp.Text='Authorized names (edit in script before running). Never store passwords in the source.';$tabAccounts.Controls.Add($accountHelp)
$accountsText=New-Object Windows.Forms.TextBox;$accountsText.Dock='Fill';$accountsText.Multiline=$true;$accountsText.ReadOnly=$true;$accountsText.ScrollBars='Vertical';$accountsText.Text="Admins: $($script:Admins -join ', ')`r`n`r`nUsers: $($script:Users -join ', ')";$tabAccounts.Controls.Add($accountsText);$accountsText.BringToFront()
$cipherPanel=New-Object Windows.Forms.TableLayoutPanel;$cipherPanel.Dock='Fill';$cipherPanel.ColumnCount=1;$cipherPanel.RowCount=5;$cipherPanel.Padding=New-Object Windows.Forms.Padding(15)
$cipherPanel.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',30)))|Out-Null
$cipherPanel.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',35)))|Out-Null
$cipherPanel.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',48)))|Out-Null
$cipherPanel.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',65)))|Out-Null
$cipherPanel.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',42)))|Out-Null
$tabCipher.Controls.Add($cipherPanel)
$label=New-Object Windows.Forms.Label;$label.Text='Paste ciphertext / Pega el texto cifrado';$cipherPanel.Controls.Add($label,0,0)
$input=New-Object Windows.Forms.TextBox;$input.Multiline=$true;$input.ScrollBars='Vertical';$input.Dock='Fill';$cipherPanel.Controls.Add($input,0,1)
$toolsPanel=New-Object Windows.Forms.FlowLayoutPanel;$toolsPanel.Dock='Fill';$cipherPanel.Controls.Add($toolsPanel,0,2)
$mode=New-Object Windows.Forms.ComboBox;$mode.DropDownStyle='DropDownList';$mode.Width=200;[void]$mode.Items.AddRange(@('Atbash','ROT13','Caesar all shifts'));$mode.SelectedIndex=0;$toolsPanel.Controls.Add($mode)
$decode=New-Object Windows.Forms.Button;$decode.Text='DECODE';$decode.Width=130;$toolsPanel.Controls.Add($decode)
$output=New-Object Windows.Forms.TextBox;$output.Multiline=$true;$output.ScrollBars='Both';$output.ReadOnly=$true;$output.Dock='Fill';$cipherPanel.Controls.Add($output,0,3)
$copy=New-Object Windows.Forms.Button;$copy.Text='COPY RESULT';$copy.Width=170;$cipherPanel.Controls.Add($copy,0,4)
$decode.Add_Click({
 if($mode.SelectedIndex -eq 0){$output.Text=Cipher $input.Text 'Atbash' 0}
 elseif($mode.SelectedIndex -eq 1){$output.Text=Cipher $input.Text 'Caesar' 13}
 else{$output.Text=(1..25|ForEach-Object {"ROT${_} : $(Cipher $input.Text 'Caesar' $_)"}) -join [Environment]::NewLine}
})
$copy.Add_Click({if($output.Text){[Windows.Forms.Clipboard]::SetText($output.Text)}})
$langPanel=New-Object Windows.Forms.FlowLayoutPanel;$langPanel.Dock='Top';$langPanel.Height=60;$tabSettings.Controls.Add($langPanel)
$langLabel=New-Object Windows.Forms.Label;$langLabel.Text='Idioma / Language';$langLabel.Width=160;$langPanel.Controls.Add($langLabel)
$langSelect=New-Object Windows.Forms.ComboBox;$langSelect.DropDownStyle='DropDownList';$langSelect.Width=180;[void]$langSelect.Items.AddRange(@('Español','English'));$langSelect.SelectedIndex=0;$langPanel.Controls.Add($langSelect)
function Set-Language {
 $es=$script:Language -eq 'es'
 $tabAudit.Text=if($es){'Auditoría'}else{'Audit'}
 $tabAccounts.Text=if($es){'Cuentas'}else{'Accounts'}
 $tabCipher.Text=if($es){'Cifrados'}else{'Ciphers'}
 $tabSettings.Text=if($es){'Configuración'}else{'Settings'}
 $scanBtn.Text=if($es){'VERIFICAR'}else{'SCAN'}
 $fixBtn.Text=if($es){'REPARAR TODO'}else{'FIX ALL'}
 $exportBtn.Text=if($es){'EXPORTAR INFORME'}else{'EXPORT REPORT'}
 $accountHelp.Text=if($es){'Cuentas autorizadas definidas en el script. No guardes contraseñas en el código.'}else{'Authorized accounts defined in script. Do not store passwords in source.'}
 $label.Text=if($es){'Pega el texto cifrado'}else{'Paste ciphertext'}
 $decode.Text=if($es){'DECODIFICAR'}else{'DECODE'}
 $copy.Text=if($es){'COPIAR RESULTADO'}else{'COPY RESULT'}
 $settings.Text=if($es){"CyberPatriot Auditor v8`r`nREPARAR TODO aplica correcciones implementadas y vuelve a verificar.`r`nLas preguntas forenses y los hallazgos sin reparación requieren revisión manual.`r`nNo se garantiza una puntuación ni cobertura completa."}else{"CyberPatriot Auditor v8`r`nFIX ALL attempts implemented repairs and rescans.`r`nForensic questions and unsupported findings require manual review.`r`nNo score or full-coverage guarantee."}
 $status.Text=if($es){'Listo. Verificar no modifica el equipo.'}else{'Ready. Scanning does not modify the computer.'}
}
$langSelect.Add_SelectedIndexChanged({$script:Language=if($langSelect.SelectedIndex -eq 0){'es'}else{'en'};Set-Language})
$settings=New-Object Windows.Forms.Label;$settings.Dock='Fill';$settings.Text='CyberPatriot Auditor v8`r`n`r`nFIX ALL attempts implemented repairs, then rescans.`r`nUnrecognized accounts, shares, and forensic answers remain review-only.`r`nNo scoring guarantees. Use only on authorized training systems.';$tabSettings.Controls.Add($settings);$settings.BringToFront();$langPanel.BringToFront()
Set-Language
[void]$form.ShowDialog()