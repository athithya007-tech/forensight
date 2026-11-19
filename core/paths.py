"""Filesystem locations. Everything for one case lives in one folder (FR-2)."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def project_root() -> Path:
    """Directory holding rules/, tools/ and web/. Works from source and from a PyInstaller bundle."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


def cases_root() -> Path:
    return Path(os.environ.get("FORENSIGHT_CASES", Path.cwd() / "cases")).resolve()


def home_dir() -> Path:
    """Per-analyst state: signing keys and intel cache."""
    p = Path(os.environ.get("FORENSIGHT_HOME", Path.home() / ".forensight"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def rules_dir() -> Path:
    return Path(os.environ.get("FORENSIGHT_RULES", project_root() / "rules"))


def tools_dirs() -> list[Path]:
    """Places to look for bundled third-party binaries (winpmem, avml, chainsaw ...)."""
    dirs = [project_root() / "tools"]
    if getattr(sys, "frozen", False):
        dirs.insert(0, Path(sys.executable).parent / "tools")
    return dirs


def find_tool(*names: str) -> str | None:
    import shutil
    for d in tools_dirs():
        for n in names:
            for cand in (d / n, d / (n + ".exe")):
                if cand.exists():
                    return str(cand)
    for n in names:
        found = shutil.which(n)
        if found:
            return found
    return None


def case_dir(case_id: str, root: Path | None = None) -> Path:
    root = root or cases_root()
    p = Path(case_id)
    if p.is_absolute() and p.exists():
        return p
    d = root / case_id
    if not d.exists():
        raise FileNotFoundError(
            f"Case {case_id} not found in {root}. Run 'forensight cases' to list cases or set FORENSIGHT_CASES."
        )
    return d
