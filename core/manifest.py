"""Chain-of-custody manifest with a SHA-256 hash chain (FR-11..14, FR-38).

entry_hash = SHA-256(prev_hash + file_hash + canonical_json(metadata))
Changing any file, editing any entry, or deleting/reordering entries breaks verification.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import stat
import threading
from pathlib import Path

from .audit import audit
from .timeutil import now_iso

GENESIS = "0" * 64
_lock = threading.Lock()
CHUNK = 1024 * 1024


def sha256_file(path: Path, on_progress=None) -> str:
    h = hashlib.sha256()
    done = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
            done += len(b)
            if on_progress:
                on_progress(done)
    return h.hexdigest()


def _meta(entry: dict) -> dict:
    return {k: entry[k] for k in ("seq", "path", "size", "collected_at", "collector", "module")}


def entry_hash(prev_hash: str, file_hash: str, meta: dict) -> str:
    payload = prev_hash + file_hash + json.dumps(meta, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def collector_id() -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    return f"{user}@{platform.node()}"


def load(case_dir: Path) -> dict:
    p = Path(case_dir) / "manifest.json"
    if not p.exists():
        return {"version": 2, "algorithm": "SHA-256", "chain": "entry_hash = SHA256(prev_hash + sha256 + meta)", "entries": []}
    return json.loads(p.read_text(encoding="utf-8"))


def save(case_dir: Path, doc: dict) -> None:
    p = Path(case_dir) / "manifest.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def make_readonly(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass


def add_artifact(case_dir: Path, path: Path, module: str, readonly: bool = True, file_hash: str | None = None) -> dict:
    """Hash a freshly collected file, append it to the chain and make it read-only."""
    case_dir = Path(case_dir)
    path = Path(path)
    rel = path.relative_to(case_dir).as_posix()
    digest = file_hash or sha256_file(path)
    with _lock:
        doc = load(case_dir)
        entries = doc["entries"]
        prev = entries[-1]["entry_hash"] if entries else GENESIS
        entry = {
            "seq": len(entries) + 1,
            "path": rel,
            "size": path.stat().st_size,
            "sha256": digest,
            "collected_at": now_iso(),
            "collector": collector_id(),
            "module": module,
            "prev_hash": prev,
        }
        entry["entry_hash"] = entry_hash(prev, digest, _meta(entry))
        entries.append(entry)
        save(case_dir, doc)
    if readonly:
        make_readonly(path)
    audit(case_dir, module, f"hashed {rel} sha256={digest}")
    return entry


def verify(case_dir: Path) -> dict:
    """Re-hash every artifact and walk the hash chain. Returns a per-entry report."""
    case_dir = Path(case_dir)
    doc = load(case_dir)
    results = []
    prev = GENESIS
    chain_ok = True
    files_ok = True
    first_break = None
    for i, e in enumerate(doc["entries"]):
        r = {"seq": e.get("seq"), "path": e.get("path"), "expected": e.get("sha256"), "status": "ok", "problems": []}
        if e.get("seq") != i + 1:
            r["problems"].append("sequence gap (entry deleted or reordered)")
        if e.get("prev_hash") != prev:
            r["problems"].append("prev_hash does not match previous entry")
        calc = entry_hash(e.get("prev_hash", ""), e.get("sha256", ""), _meta(e)) if all(k in e for k in ("seq", "path", "size", "collected_at", "collector", "module")) else None
        if calc != e.get("entry_hash"):
            r["problems"].append("entry_hash mismatch (entry edited)")
        chain_broken_here = bool(r["problems"])
        f = case_dir / e["path"]
        if not f.exists():
            r["actual"] = None
            r["problems"].append("file missing")
            files_ok = False
        else:
            actual = sha256_file(f)
            r["actual"] = actual
            if actual != e["sha256"]:
                r["problems"].append("file hash mismatch (file modified)")
                files_ok = False
        if chain_broken_here:
            chain_ok = False
            first_break = first_break or e.get("seq")
        if r["problems"]:
            r["status"] = "mismatch"
        results.append(r)
        prev = e.get("entry_hash", "")
    # files under raw/ that the manifest does not know about
    known = {e["path"] for e in doc["entries"]}
    extra = []
    raw = case_dir / "raw"
    if raw.exists():
        for p in raw.rglob("*"):
            if p.is_file() and p.relative_to(case_dir).as_posix() not in known:
                extra.append(p.relative_to(case_dir).as_posix())
    from .signing import verify_file
    sig = verify_file(case_dir / "manifest.json", case_dir / "manifest.sig") if (case_dir / "manifest.sig").exists() else {"valid": None, "reason": "manifest not signed yet"}
    mismatches = sum(1 for r in results if r["status"] != "ok")
    return {
        "ok": mismatches == 0 and chain_ok and not extra and sig.get("valid") is not False,
        "entries": results,
        "total": len(results),
        "mismatches": mismatches,
        "chain_ok": chain_ok,
        "files_ok": files_ok,
        "first_break": first_break,
        "unlisted_files": extra,
        "root_hash": doc["entries"][-1]["entry_hash"] if doc["entries"] else GENESIS,
        "manifest_signature": sig,
        "verified_at": now_iso(),
    }


def sign_manifest(case_dir: Path) -> dict:
    from .signing import sign_file
    case_dir = Path(case_dir)
    doc = sign_file(case_dir / "manifest.json", case_dir / "manifest.sig", {"signed_at": now_iso()})
    audit(case_dir, "custody", f"manifest signed (Ed25519) sha256={doc['sha256']}")
    return doc
