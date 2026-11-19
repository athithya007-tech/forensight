from analyzer import rules, sigma
from analyzer.metrics import coverage


def rec(ts, kind="evtx", **fields):
    return {"ts": ts, "kind": kind, "fields": fields, "evidence_ref": f"x#{ts}{fields.get('EventID')}", "host": "H", "source": "s"}


def test_operators():
    f = {"EventID": 4625, "CommandLine": "powershell -enc AAAA", "rport": "4444", "IpAddress": "-"}
    assert rules.matches(f, {"EventID": [4624, 4625]})
    assert rules.matches(f, {"commandline|contains": "-ENC"})
    assert rules.matches(f, {"CommandLine|re": r"-enc\s+\w+"})
    assert rules.matches(f, {"rport": 4444})
    assert not rules.matches(f, {"IpAddress|exists": True})
    assert rules.matches(f, {"any": [{"EventID": 1}, {"rport|gte": 4000}]})
    assert not rules.matches(f, {"not": {"EventID": 4625}})


def test_brute_force_threshold_followed_by_success():
    rule = {"id": "T", "title": "bf", "kind": "evtx", "severity": "High", "attck_id": "T1110",
            "match": {"EventID": 4625}, "threshold": {"count": 5, "window": "5m", "group_by": "IpAddress"},
            "followed_by": {"within": "10m", "match": {"EventID": 4624}, "same": ["IpAddress"]},
            "description": "{count} fails then {success_TargetUserName}"}
    recs = [rec(f"2026-11-19T10:00:{i:02d}.000Z", EventID=4625, IpAddress="1.1.1.1") for i in range(6)]
    recs += [rec("2026-11-19T10:00:30.000Z", EventID=4625, IpAddress="2.2.2.2")]  # only 1 failure from another IP
    recs += [rec("2026-11-19T10:01:00.000Z", EventID=4624, IpAddress="1.1.1.1", TargetUserName="admin")]
    hits = rules.evaluate(rule, recs)
    assert len(hits) == 1 and hits[0]["description"] == "6 fails then admin"
    # 4 failures only: below threshold
    assert not rules.evaluate(rule, recs[:4] + recs[-1:])
    # no success -> no hit unless unfollowed_severity is set
    assert not rules.evaluate(rule, recs[:6])
    rule["unfollowed_severity"] = "Medium"
    h = rules.evaluate(rule, recs[:6])
    assert len(h) == 1 and h[0]["severity"] == "Medium"


def test_failures_spread_beyond_window_do_not_fire():
    rule = {"id": "T", "title": "bf", "kind": "evtx", "severity": "High", "match": {"EventID": 4625},
            "threshold": {"count": 5, "window": "5m", "group_by": "IpAddress"}}
    recs = [rec(f"2026-11-19T1{i}:00:00.000Z", EventID=4625, IpAddress="1.1.1.1") for i in range(6)]
    assert not rules.evaluate(rule, recs)


def test_rule_files_load_and_cover_15_plus_techniques():
    loaded = rules.load_rules()
    assert len(loaded) >= 25
    assert all(r.get("id") and (r.get("attck_id") or r.get("context")) for r in loaded)
    assert len(coverage()) >= 15


def test_sigma_condition_parser():
    res = {"selection": True, "filter": False, "sel_a": True, "sel_b": False}
    assert sigma._condition("selection and not filter", res)
    assert sigma._condition("1 of sel_*", res)
    assert not sigma._condition("all of sel_*", res)
    assert sigma._condition("(sel_b or selection) and not filter", res)


def test_sigma_native_match_on_sysmon_and_4688():
    s = {"title": "net user add", "logsource": {"category": "process_creation", "product": "windows"},
         "detection": {"img": {"Image|endswith": ["\\net.exe"]}, "cli": {"CommandLine|contains|all": ["user", "/add"]}, "condition": "all of img and cli"}}
    s["detection"]["condition"] = "img and cli"
    sysmon = rec("t1", EventID=1, Channel="Microsoft-Windows-Sysmon/Operational", Image=r"C:\Windows\System32\net.exe", CommandLine="net user x y /add")
    sec = rec("t2", EventID=4688, Channel="Security", NewProcessName=r"C:\Windows\System32\net.exe", CommandLine="net user x y /add")
    other = rec("t3", EventID=4688, Channel="Security", NewProcessName=r"C:\Windows\System32\net.exe", CommandLine="net view")
    assert len(sigma.evaluate_native(s, [sysmon, sec, other])) == 2
