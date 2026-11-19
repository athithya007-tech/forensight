import json
import os
import stat

from core import severity as sev
from core.case import create_case, load_case, next_case_id
from core.manifest import add_artifact, sign_manifest, verify
from core.timeutil import parse_duration, to_iso


def test_timestamps_to_utc_with_ms():
    assert to_iso("2026-11-19T10:04:12.3456789Z") == "2026-11-19T10:04:12.345Z"
    assert to_iso("2026-11-19 10:04:12", "Asia/Kolkata") == "2026-11-19T04:34:12.000Z"
    assert to_iso("2026-11-19T10:04:12+05:30") == "2026-11-19T04:34:12.000Z"
    assert to_iso(1763546652) == "2025-11-19T10:04:12.000Z"
    assert parse_duration("5m").total_seconds() == 300


def test_case_id_format_and_case_json(tmp_path):
    d = create_case("Lab", "Asha", "notes", root=tmp_path)
    c = load_case(d)
    assert c["id"].startswith("CASE-") and len(c["id"]) == len("CASE-20261119-001")
    assert {"id", "investigator", "host", "os", "start_time_utc", "notes"} <= set(c)
    assert next_case_id(tmp_path).endswith("-002")
    assert (d / "audit.log").read_text().count("created") == 1


def _case_with_files(tmp_path, n=3):
    d = create_case("Lab", "Asha", root=tmp_path)
    for i in range(n):
        p = d / f"raw/live/f{i}.json"
        p.write_text(json.dumps({"i": i}))
        add_artifact(d, p, "test")
    sign_manifest(d)
    return d


def test_manifest_chain_verifies_and_files_readonly(tmp_path):
    d = _case_with_files(tmp_path)
    r = verify(d)
    assert r["ok"] and r["chain_ok"] and r["total"] == 3 and r["mismatches"] == 0
    assert not os.stat(d / "raw/live/f0.json").st_mode & stat.S_IWUSR


def test_one_byte_edit_is_detected(tmp_path):
    d = _case_with_files(tmp_path)
    p = d / "raw/live/f1.json"
    p.chmod(0o644)
    data = bytearray(p.read_bytes())
    data[0] ^= 1
    p.write_bytes(bytes(data))
    r = verify(d)
    assert not r["ok"] and r["mismatches"] == 1
    assert "file hash mismatch" in " ".join(r["entries"][1]["problems"])


def test_deleting_or_editing_entry_breaks_chain(tmp_path):
    d = _case_with_files(tmp_path)
    m = json.loads((d / "manifest.json").read_text())
    m["entries"].pop(1)
    (d / "manifest.json").write_text(json.dumps(m))
    r = verify(d)
    assert not r["chain_ok"] and r["first_break"] == 3
    assert r["manifest_signature"]["valid"] is False

    d2 = _case_with_files(tmp_path / "b")
    m = json.loads((d2 / "manifest.json").read_text())
    m["entries"][0]["collected_at"] = "2020-01-01T00:00:00.000Z"
    (d2 / "manifest.json").write_text(json.dumps(m))
    assert not verify(d2)["chain_ok"]


def test_unlisted_file_is_reported(tmp_path):
    d = _case_with_files(tmp_path)
    (d / "raw/live/planted.json").write_text("{}")
    r = verify(d)
    assert not r["ok"] and r["unlisted_files"] == ["raw/live/planted.json"]


def test_score_and_verdict():
    assert sev.score({"Critical": 1, "High": 1, "Medium": 1, "Low": 1}) == 40
    assert sev.score({"Critical": 9}) == 100
    assert sev.verdict(0) == "Clean" and sev.verdict(19) == "Clean"
    assert sev.verdict(20) == "Suspicious" and sev.verdict(59) == "Suspicious"
    assert sev.verdict(60) == "Compromised"
    assert sev.lower("High") == "Medium" and sev.lower("Info") == "Info"
