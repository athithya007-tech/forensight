import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIGHT_CASES", str(tmp_path / "cases"))
    monkeypatch.setenv("FORENSIGHT_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:9")  # never reach a real model in tests
    import api.llm
    monkeypatch.setattr(api.llm, "HOST", "http://127.0.0.1:9")
    yield tmp_path


@pytest.fixture
def demo_case():
    from analyzer.runner import run
    from demo.generator import generate

    def make(steps=None, analyze=True, **kw):
        d = generate(steps=steps, **kw)
        if analyze:
            run(d)
        return d
    return make
