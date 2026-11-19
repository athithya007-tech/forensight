"""Local LLM via Ollama (optional). No case data leaves the analyst machine."""
from __future__ import annotations

import json
import os
import urllib.request

HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
MODEL = os.environ.get("FORENSIGHT_MODEL", "llama3.1:8b")


def available() -> bool:
    try:
        with urllib.request.urlopen(f"{HOST}/api/tags", timeout=1.5) as r:
            return r.status == 200
    except Exception:
        return False


def generate(prompt: str, system: str | None = None, timeout: int = 120) -> str | None:
    body = {"model": MODEL, "prompt": prompt, "stream": False, "options": {"temperature": 0.1}}
    if system:
        body["system"] = system
    try:
        req = urllib.request.Request(f"{HOST}/api/generate", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()).get("response", "").strip() or None
    except Exception:
        return None


def stream(prompt: str, system: str | None = None, timeout: int = 180):
    body = {"model": MODEL, "prompt": prompt, "stream": True, "options": {"temperature": 0.1}}
    if system:
        body["system"] = system
    req = urllib.request.Request(f"{HOST}/api/generate", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        for line in r:
            if line.strip():
                d = json.loads(line)
                if d.get("response"):
                    yield d["response"]
                if d.get("done"):
                    break
