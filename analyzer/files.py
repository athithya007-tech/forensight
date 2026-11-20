"""YARA + hash reputation over collected files (US-008)."""
from __future__ import annotations

import json
from pathlib import Path

from core.paths import rules_dir


def compile_rules(log):
    try:
        import yara
    except ImportError:
        log("yara-python not installed; YARA scan skipped (hash reputation still runs)", "WARN")
        return None
    files = {p.stem: str(p) for p in (rules_dir() / "yara").glob("*.yar*")}
    if not files:
        return None
    try:
        return yara.compile(filepaths=files)
    except Exception as e:  # noqa: BLE001
        log(f"YARA compile error: {e}", "ERROR")
        return None


def scan(loader, intel, log) -> int:
    n0 = len(loader.records)
    idx_path = loader.work / "artifacts/files_index.json"
    index = json.loads(idx_path.read_text()) if idx_path.exists() else []
    rules = compile_rules(log)
    out = []
    for item in index:
        # a file the antivirus quarantined is known only by its hash: no YARA, but hash reputation still runs
        copy = loader.work / Path(item["copy"]).relative_to("raw") if item.get("copy") else None
        ref = item["copy"] or f"raw/artifacts/files_index.json#{item['original_path']}"
        if rules is not None and copy is not None and copy.exists():
            try:
                for m in rules.match(str(copy), timeout=30):
                    f = {"rule": m.rule, "namespace": m.namespace, "tags": list(m.tags), "path": item["original_path"],
                         "sha256": item["sha256"], "meta": dict(m.meta)}
                    loader.add("yara", "yara", item.get("mtime"), f, f"{ref}#yara={m.rule}")
                    out.append(f)
            except Exception as e:  # noqa: BLE001
                log(f"YARA scan failed on {copy.name}: {e}", "WARN")
        rep = intel.hash(item.get("sha256"))
        if rep.get("reputation") in ("malicious", "suspicious"):
            f = {"path": item["original_path"], "sha256": item["sha256"], **rep}
            loader.add("hash_rep", "hash-reputation", item.get("mtime"), f, f"{ref}#sha256")
    # process executables too (hash reputation only)
    for r in [r for r in loader.records if r["kind"] == "process" and r["fields"].get("sha256")]:
        rep = intel.hash(r["fields"]["sha256"])
        if rep.get("reputation") == "malicious":
            loader.add("hash_rep", "hash-reputation", r["ts"], {"path": r["fields"].get("path"),
                       "sha256": r["fields"]["sha256"], "pid": r["fields"].get("pid"), **rep}, r["evidence_ref"])
    return len(loader.records) - n0
