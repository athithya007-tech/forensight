# Lab setup (PRD section 9)

Run everything inside an isolated virtual lab you own. Never on college or public networks.

| VM | OS | RAM | Role |
|---|---|---|---|
| Victim-WIN | Windows 10/11 evaluation ISO | 4 GB | Target. Sysmon, PowerShell logging and audit policy enabled |
| Victim-LNX | Ubuntu 22.04/24.04 | 2 GB | SSH brute-force scenario |
| Attacker | Kali Linux | 2 GB | Runs steps 1-2 |
| Analyst | your laptop | 8 GB | `forensight analyze / serve / report` |

1. VirtualBox/VMware **host-only** network, no internet for the victims. Take a clean **snapshot** of each victim.
2. On Victim-WIN (admin PowerShell):
   ```powershell
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   auditpol /set /subcategory:"User Account Management" /success:enable
   auditpol /set /subcategory:"Security Group Management" /success:enable
   auditpol /set /subcategory:"Process Creation" /success:enable
   auditpol /set /subcategory:"Other Object Access Events" /success:enable   # 4698 task created
   reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
   reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
   wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
   sysmon64 -accepteula -i sysmonconfig.xml        # e.g. SwiftOnSecurity config
   Add-MpPreference -ExclusionPath $env:TEMP        # LAB ONLY: keeps EICAR + WinPmem from being quarantined
   ```
3. Create a weak-password local admin `admin` / `LabAdmin1!` and enable RDP.
4. **Baseline** (clean snapshot): `forensight collect --baseline --case <id>`.
5. Attack: on Kali `./attacker.sh 192.168.56.10` (steps 1-2), then on the victim `attack.ps1 -Steps 3,4,5,6,7,8`.
6. Collect from the USB drive: `forensight.exe collect --case <id> --out E:\evidence --profile full`.
7. On the analyst machine: `forensight analyze`, `forensight report`, `forensight serve`.

Put third-party binaries in `tools/` next to the collector: `winpmem_mini_x64_rc2.exe` (Windows RAM),
`avml` (Linux RAM), optionally `chainsaw` with its `mappings/` folder. Volatility 3 runs on the analyst machine
(`pip install volatility3`, with Windows symbol packs pre-downloaded).

**Step 8 note:** clearing the Security log destroys the 4625/4624/4720/4732/4698 records written in steps 1-6.
ForenSight still detects those steps from RDP (RdpCoreTS 140, LocalSessionManager 21), Sysmon, PowerShell,
TaskScheduler logs, live state and the baseline diff. This is a good demo talking point.

`attack_menu.html` is the printable card for judges (US-014).
