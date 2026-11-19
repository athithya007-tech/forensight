"""Time helpers. Every timestamp ForenSight stores is UTC ISO-8601 with millisecond precision."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

UTC = timezone.utc


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    """Format a datetime as 2026-11-19T10:04:12.345Z (naive values are treated as UTC)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def now_iso() -> str:
    return iso(now_utc())


_FRACTION = re.compile(r"\.(\d+)")


def parse_ts(value, default_tz: str | None = None) -> datetime | None:
    """Parse many timestamp shapes into an aware UTC datetime.

    Naive timestamps are interpreted in ``default_tz`` (an IANA name) or UTC.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        # epoch seconds (or ms if obviously too large)
        v = float(value)
        if v > 1e12:
            v /= 1000.0
        return datetime.fromtimestamp(v, UTC)
    else:
        s = str(value).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        s = s.replace(" UTC", "+00:00")
        # Python only accepts up to 6 fractional digits
        m = _FRACTION.search(s)
        if m and len(m.group(1)) > 6:
            s = s[: m.start(1)] + m.group(1)[:6] + s[m.end(1):]
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S"):
                try:
                    dt = datetime.strptime(s, fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
    if dt.tzinfo is None:
        tz = ZoneInfo(default_tz) if default_tz else UTC
        dt = dt.replace(tzinfo=tz)
    return dt.astimezone(UTC)


def to_iso(value, default_tz: str | None = None) -> str | None:
    dt = parse_ts(value, default_tz)
    return iso(dt) if dt else None


_DUR = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*$")


def parse_duration(value) -> timedelta:
    """'5m' -> 5 minutes, '30s', '2h', '1d'; bare numbers are seconds."""
    if isinstance(value, (int, float)):
        return timedelta(seconds=value)
    m = _DUR.match(str(value))
    if not m:
        raise ValueError(f"Bad duration {value!r}; use e.g. 30s, 5m, 2h, 1d")
    n = float(m.group(1))
    unit = m.group(2) or "s"
    names = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    return timedelta(**{names[unit]: n})


def local_tz_name() -> str:
    """Best-effort IANA name of this machine's timezone (falls back to UTC offset string)."""
    try:
        import os
        if os.environ.get("TZ"):
            return os.environ["TZ"]
        link = os.path.realpath("/etc/localtime")
        if "zoneinfo/" in link:
            return link.split("zoneinfo/", 1)[1]
    except Exception:
        pass
    off = datetime.now().astimezone().utcoffset() or timedelta(0)
    mins = int(off.total_seconds() // 60)
    if mins == 0:
        return "UTC"
    sign = "+" if mins >= 0 else "-"
    return f"UTC{sign}{abs(mins)//60:02d}:{abs(mins)%60:02d}"
