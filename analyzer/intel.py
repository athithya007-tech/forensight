"""Threat intel: offline lists always; VirusTotal / AbuseIPDB by hash/IP only when keys are set (FR-19).
File contents are never uploaded. API keys come only from environment variables."""
from __future__ import annotations

import ipaddress
import json
import os
import urllib.request
from pathlib import Path

from core.paths import rules_dir


def _list(name: str) -> set[str]:
    p = rules_dir() / "intel" / name
    if not p.exists():
        return set()
    return {l.split("#")[0].strip().lower() for l in p.read_text().splitlines() if l.split("#")[0].strip()}


def is_public(ip: str | None) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)
    except (ValueError, TypeError):
        return False


class Intel:
    def __init__(self, case_dir: Path, online: bool, log):
        self.bad_ips = _list("bad_ips.txt")
        self.bad_hashes = _list("bad_hashes.txt")
        self.online = online
        self.log = log
        self.vt_key = os.environ.get("VT_API_KEY")
        self.abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
        self.cache_path = case_dir / "analysis/intel_cache.json"
        self.cache = json.loads(self.cache_path.read_text()) if self.cache_path.exists() else {}
        if online and not (self.vt_key or self.abuse_key):
            log("--online given but no VT_API_KEY / ABUSEIPDB_API_KEY set; running offline", "WARN")

    def save(self):
        self.cache_path.write_text(json.dumps(self.cache, indent=1))

    def _get(self, url: str, headers: dict) -> dict | None:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except Exception as e:  # noqa: BLE001
            self.log(f"intel lookup failed for {url.split('?')[0]}: {e}", "WARN")
            return None

    def ip(self, ip: str | None) -> dict:
        if not ip:
            return {"reputation": "unknown"}
        if ip.lower() in self.bad_ips:
            return {"reputation": "malicious", "source": "offline-list"}
        if not is_public(ip):
            return {"reputation": "internal"}
        key = f"ip:{ip}"
        if key in self.cache:
            return self.cache[key]
        res = {"reputation": "unknown"}
        if self.online and self.abuse_key:
            d = self._get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                          {"Key": self.abuse_key, "Accept": "application/json"})
            if d and "data" in d:
                score = d["data"].get("abuseConfidenceScore", 0)
                res = {"reputation": "malicious" if score >= 50 else ("suspicious" if score >= 10 else "clean"),
                       "score": score, "source": "AbuseIPDB", "country": d["data"].get("countryCode")}
        self.cache[key] = res
        return res

    def hash(self, sha256: str | None) -> dict:
        if not sha256:
            return {"reputation": "unknown"}
        if sha256.lower() in self.bad_hashes:
            return {"reputation": "malicious", "source": "offline-list"}
        key = f"hash:{sha256}"
        if key in self.cache:
            return self.cache[key]
        res = {"reputation": "unknown"}
        if self.online and self.vt_key:
            d = self._get(f"https://www.virustotal.com/api/v3/files/{sha256}", {"x-apikey": self.vt_key})
            if d and "data" in d:
                st = d["data"]["attributes"].get("last_analysis_stats", {})
                mal = st.get("malicious", 0)
                res = {"reputation": "malicious" if mal >= 3 else ("suspicious" if mal else "clean"),
                       "detections": mal, "source": "VirusTotal"}
        self.cache[key] = res
        return res
