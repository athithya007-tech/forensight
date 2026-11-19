"""Stretch US-022: Telegram / SMTP alert when a Critical finding appears. Configured in config.yaml;
secrets come from environment variables (FORENSIGHT_TELEGRAM_TOKEN, FORENSIGHT_SMTP_PASSWORD)."""
from __future__ import annotations

import json
import os
import smtplib
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path

import yaml

from core.paths import home_dir


def load_config() -> dict:
    for p in (Path.cwd() / "config.yaml", home_dir() / "config.yaml"):
        if p.exists():
            return yaml.safe_load(p.read_text()) or {}
    return {}


def notify_critical(case: dict, findings: list[dict], log) -> None:
    crit = [f for f in findings if f["severity"] == "Critical"]
    cfg = (load_config().get("alerts") or {})
    if not crit or not cfg:
        return
    text = f"[ForenSight] {len(crit)} CRITICAL finding(s) on {case.get('host')} ({case['id']}):\n" + \
        "\n".join(f"- {f['title']} ({f['attck_id']})" for f in crit[:10])
    tg = cfg.get("telegram") or {}
    token = os.environ.get("FORENSIGHT_TELEGRAM_TOKEN")
    if tg.get("chat_id") and token:
        data = urllib.parse.urlencode({"chat_id": tg["chat_id"], "text": text}).encode()
        urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data=data, timeout=10)
        log("critical alert sent via Telegram")
    sm = cfg.get("smtp") or {}
    if sm.get("host") and sm.get("to"):
        msg = EmailMessage()
        msg["Subject"] = f"ForenSight critical alert: {case['id']}"
        msg["From"] = sm.get("from", "forensight@localhost")
        msg["To"] = sm["to"]
        msg.set_content(text)
        with smtplib.SMTP(sm["host"], int(sm.get("port", 587)), timeout=15) as s:
            if sm.get("starttls", True):
                s.starttls()
            if sm.get("user"):
                s.login(sm["user"], os.environ.get("FORENSIGHT_SMTP_PASSWORD", ""))
            s.send_message(msg)
        log("critical alert sent via SMTP")
