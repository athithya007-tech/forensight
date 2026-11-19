"""timeline.db: one SQLite file per case (section 15.6)."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, name TEXT, investigator TEXT, host TEXT, os TEXT,
  created_at TEXT, score INTEGER, verdict TEXT
);
CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY, case_id TEXT, path TEXT, size INTEGER, sha256 TEXT,
  prev_hash TEXT, entry_hash TEXT, collected_at TEXT, module TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, case_id TEXT, timestamp_utc TEXT, original_ts TEXT, original_tz TEXT,
  host TEXT, source TEXT, event_type TEXT, description TEXT, severity TEXT, attck_id TEXT,
  tactic TEXT, phase TEXT, phase_index INTEGER, evidence_ref TEXT, rule_ids TEXT, raw_json TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(case_id, timestamp_utc);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, case_id TEXT, rule_id TEXT, title TEXT, description TEXT, severity TEXT,
  original_severity TEXT, confidence REAL, attck_id TEXT, tactic TEXT, playbook TEXT, event_ids TEXT,
  evidence_refs TEXT, first_seen TEXT, last_seen TEXT, pre_existing INTEGER DEFAULT 0, engine TEXT
);
CREATE TABLE IF NOT EXISTS entities (
  id TEXT, case_id TEXT, type TEXT, value TEXT, label TEXT, severity TEXT, event_ids TEXT,
  PRIMARY KEY (case_id, id)
);
CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY, case_id TEXT, source_entity TEXT, target_entity TEXT, type TEXT,
  event_id INTEGER, ts TEXT
);
CREATE TABLE IF NOT EXISTS baseline_items (
  id INTEGER PRIMARY KEY, case_id TEXT, category TEXT, key TEXT, value_json TEXT, snapshot TEXT
);
CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY, case_id TEXT, role TEXT, content TEXT, citations TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS iocs (
  id INTEGER PRIMARY KEY, case_id TEXT, type TEXT, value TEXT, context TEXT, severity TEXT, first_seen TEXT
);
"""

ANALYSIS_TABLES = ["artifacts", "events", "findings", "entities", "edges", "baseline_items", "iocs"]


def connect(case_dir: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(Path(case_dir) / "timeline.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def reset_analysis(conn: sqlite3.Connection, case_id: str) -> None:
    for t in ANALYSIS_TABLES:
        conn.execute(f"DELETE FROM {t} WHERE case_id = ?", (case_id,))
    conn.commit()


def rows(conn: sqlite3.Connection, sql: str, params=()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


JSON_COLS = {"playbook", "event_ids", "evidence_refs", "rule_ids", "raw_json", "citations", "value_json"}


def decode(row: dict) -> dict:
    for k in list(row):
        if k in JSON_COLS and isinstance(row[k], str):
            try:
                row[k] = json.loads(row[k])
            except json.JSONDecodeError:
                pass
    return row
