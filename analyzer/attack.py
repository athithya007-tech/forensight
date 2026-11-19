"""MITRE ATT&CK technique catalog and Navigator layer export (US-010, FR-41)."""
from __future__ import annotations

TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
           "Collection", "Command and Control", "Exfiltration", "Impact"]

TACTIC_SHORT = {t: t.lower().replace(" ", "-") for t in TACTICS}

# technique id -> (name, primary tactic)
TECHNIQUES = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement"),
    "T1021.004": ("SSH", "Lateral Movement"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1136": ("Create Account", "Persistence"),
    "T1136.001": ("Local Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1543.002": ("Systemd Service", "Persistence"),
    "T1543.003": ("Windows Service", "Persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "Persistence"),
    "T1053.003": ("Cron", "Persistence"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1070.001": ("Clear Windows Event Logs", "Defense Evasion"),
    "T1070.003": ("Clear Command History", "Defense Evasion"),
    "T1562.001": ("Disable or Modify Tools", "Defense Evasion"),
    "T1564": ("Hide Artifacts", "Defense Evasion"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1204.002": ("Malicious File", "Execution"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1098.004": ("SSH Authorized Keys", "Persistence"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
}


def technique(tid: str | None) -> dict:
    if not tid:
        return {"id": None, "name": None, "tactic": None}
    name, tactic = TECHNIQUES.get(tid, TECHNIQUES.get(tid.split(".")[0], (tid, "Execution")))
    return {"id": tid, "name": name, "tactic": tactic}


def tactic_of(tid: str | None) -> str | None:
    return technique(tid)["tactic"] if tid else None


def navigator_layer(case: dict, counts: dict[str, int]) -> dict:
    """ATT&CK Navigator v4.5 layer; score = finding count per technique."""
    mx = max(counts.values(), default=1)
    return {
        "name": f"ForenSight {case.get('id')}",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Techniques detected in {case.get('id')} ({case.get('host')})",
        "sorting": 3,
        "layout": {"layout": "side", "showName": True},
        "hideDisabled": False,
        "techniques": [
            {"techniqueID": tid, "tactic": TACTIC_SHORT.get(tactic_of(tid) or "", None), "score": c,
             "color": "", "comment": f"{c} finding(s)", "enabled": True, "showSubtechniques": True}
            for tid, c in sorted(counts.items())
        ],
        "gradient": {"colors": ["#fde68a", "#f97316", "#ef4444"], "minValue": 0, "maxValue": mx},
        "legendItems": [],
        "metadata": [{"name": "case", "value": case.get("id", "")}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#121826",
    }
