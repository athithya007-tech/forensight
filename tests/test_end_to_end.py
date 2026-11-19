"""End-to-end on the recorded demo case (PRD NFR 'Testing') plus the success metrics of section 12."""
import json

import pytest
from fastapi.testclient import TestClient

from analyzer.metrics import evaluate
from api.report import generate as make_report
from core.manifest import verify
from core.signing import verify_file


def techniques(case_dir):
    return {f["attck_id"].split(".")[0] for f in json.loads((case_dir / "analysis/findings.json").read_text())}


def test_all_8_steps_detected_even_after_log_wipe(demo_case):
    d = demo_case()  # step 8 wipes the Security log
    m = evaluate(d)
    assert m["steps_detected"] == 8, m
    assert all(s["closest_finding_delta_s"] <= 1.0 for s in m["steps"]), "timeline accuracy within 1 s"
    s = json.loads((d / "analysis/summary.json").read_text())
    assert s["verdict"] == "Compromised"


def test_all_8_steps_detected_with_security_log_intact(demo_case):
    d = demo_case(steps=[1, 2, 3, 4, 5, 6, 7])
    assert evaluate(d)["steps_detected"] == 7
    findings = json.loads((d / "analysis/findings.json").read_text())
    rules = {f["rule_id"] for f in findings}
    assert {"FS-WIN-001", "FS-WIN-005", "FS-WIN-006", "FS-WIN-010"} <= rules  # primary Security-log rules
    assert not any(r.startswith("FS-DIFF") for r in rules)  # fallbacks suppressed when primary evidence exists


def test_clean_host_has_no_findings(demo_case):
    d = demo_case(steps=[])
    s = json.loads((d / "analysis/summary.json").read_text())
    assert s["findings"] == 0 and s["verdict"] == "Clean"


@pytest.mark.parametrize("steps", [[1, 2, 5, 7], [3, 4], [6, 8]])
def test_judges_pick_detects_exactly_the_chosen_steps(demo_case, steps):
    from demo.generator import STEPS
    d = demo_case(steps=steps)
    expected = {t.split(".")[0] for s in steps for t in STEPS[s][1]}
    got = techniques(d) - {"T1027"}  # Sigma obfuscation rule rides along with step 3
    assert got == expected, (steps, got, expected)


def test_report_is_signed_and_tamper_evident(demo_case):
    d = demo_case(steps=[1, 3, 7])
    out = make_report(d)
    pdf = d / "report/report.pdf"
    assert pdf.read_bytes()[:4] == b"%PDF"
    assert verify_file(pdf, d / "report/report.sig")["valid"]
    data = bytearray(pdf.read_bytes())
    data[len(data) // 2] ^= 0xFF
    pdf.write_bytes(bytes(data))
    assert not verify_file(pdf, d / "report/report.sig")["valid"]
    stix = json.loads((d / "report/iocs.stix.json").read_text())
    assert stix["type"] == "bundle" and any(o["type"] == "indicator" and "192.168.56.20" in o["pattern"] for o in stix["objects"])
    assert "timeline.csv" in {p.name for p in (d / "report").iterdir()}
    assert verify(d)["ok"]  # analysis never changed the evidence


def test_api_endpoints(demo_case):
    from api.main import app
    d = demo_case()
    make_report(d)
    c = TestClient(app)
    cid = d.name
    assert c.get("/api/cases").json()[0]["id"] == cid
    s = c.get(f"/api/cases/{cid}/summary").json()
    assert s["verdict"] == "Compromised" and len(s["top_findings"]) == 5
    ev = c.get(f"/api/cases/{cid}/events", params={"severity": "High,Critical", "q": "4444"}).json()
    assert ev["total"] >= 1 and all(e["severity"] in ("High", "Critical") for e in ev["items"])
    g = c.get(f"/api/cases/{cid}/graph").json()
    types = {n["type"] for n in g["nodes"]}
    assert {"ip", "user", "process", "file", "registry", "task"} <= types
    assert {"logged_in_as", "spawned", "wrote", "connected_to", "persisted_via"} <= {e["type"] for e in g["edges"]}
    procs = c.get(f"/api/cases/{cid}/processes").json()
    assert procs["flagged"] >= 2
    net = c.get(f"/api/cases/{cid}/network").json()
    assert net[0]["rport"] == 4444 and net[0]["severity"] == "High"
    layer = c.get(f"/api/cases/{cid}/attack/layer").json()
    assert layer["domain"] == "enterprise-attack" and all(t["score"] >= 1 for t in layer["techniques"])
    diff = c.get(f"/api/cases/{cid}/diff").json()
    assert {i["key"] for i in diff["items"] if i["change"] == "Added"} >= {"support_backup", "Administrators:support_backup"}
    v = c.post(f"/api/cases/{cid}/verify").json()
    assert v["ok"] and v["report_signature"]["valid"]
    pv = c.get(f"/api/verify/{cid}").json()
    assert pv["report_signature"]["valid"] and pv["manifest"]["ok"]
    raw_ref = next(e["evidence_ref"] for e in ev["items"] if e["evidence_ref"].startswith("raw/"))
    item = c.get(f"/api/cases/{cid}/evidence/item", params={"ref": raw_ref}).json()
    assert item["manifest"]["sha256"] and item["event"]
    mem_ref = next(e["evidence_ref"] for e in ev["items"] if e["evidence_ref"].startswith("analysis/"))
    assert c.get(f"/api/cases/{cid}/evidence/item", params={"ref": mem_ref}).json()["is_original_evidence"] is False
    lines = [json.loads(l) for l in c.post(f"/api/cases/{cid}/chat", json={"question": "How did the attacker get in?"}).text.splitlines()]
    done = lines[-1]
    assert done["type"] == "done" and done["citations"] and "[E" in done["answer"]
    with c.websocket_connect(f"/ws/cases/{cid}/progress") as ws:
        assert json.loads(ws.receive_text())["module"]


def test_linux_ssh_scenario(demo_case):
    from analyzer.runner import run
    from demo.generator import generate_linux
    d = generate_linux()
    s = run(d)
    assert {"T1110", "T1136.001", "T1059.004", "T1053.003", "T1070.003"} <= set(s["techniques"])
    assert evaluate(d)["steps_detected"] == 4
