"""Severity levels, compromise score and verdict (FR-20, FR-33)."""
from __future__ import annotations

LEVELS = ["Info", "Low", "Medium", "High", "Critical"]
RANK = {s: i for i, s in enumerate(LEVELS)}
WEIGHTS = {"Critical": 25, "High": 10, "Medium": 4, "Low": 1, "Info": 0}


def normalize(sev: str | None) -> str:
    if not sev:
        return "Info"
    for s in LEVELS:
        if s.lower() == str(sev).strip().lower():
            return s
    return "Info"


def max_sev(*sevs: str) -> str:
    return max((normalize(s) for s in sevs if s), key=lambda s: RANK[s], default="Info")


def lower(sev: str) -> str:
    return LEVELS[max(0, RANK[normalize(sev)] - 1)]


def score(counts: dict[str, int]) -> int:
    return min(100, sum(WEIGHTS[s] * int(counts.get(s, 0)) for s in WEIGHTS))


def verdict(score_value: int) -> str:
    if score_value >= 60:
        return "Compromised"
    if score_value >= 20:
        return "Suspicious"
    return "Clean"
