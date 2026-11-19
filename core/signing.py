"""Ed25519 signing of the manifest and the PDF report (FR-39, US-018)."""
from __future__ import annotations

import base64
import json
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from .paths import home_dir


def _key_paths() -> tuple[Path, Path]:
    d = home_dir() / "keys"
    d.mkdir(parents=True, exist_ok=True)
    return d / "signing.key", d / "signing.pub"


def load_or_create_key() -> SigningKey:
    priv, pub = _key_paths()
    if priv.exists():
        return SigningKey(base64.b64decode(priv.read_text().strip()))
    sk = SigningKey.generate()
    priv.write_text(base64.b64encode(bytes(sk)).decode())
    try:
        priv.chmod(0o600)
    except OSError:
        pass
    pub.write_text(base64.b64encode(bytes(sk.verify_key)).decode())
    return sk


def public_key_b64() -> str:
    return base64.b64encode(bytes(load_or_create_key().verify_key)).decode()


def fingerprint(pub_b64: str) -> str:
    import hashlib
    h = hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


def sign_file(path: Path, sig_path: Path, extra: dict | None = None) -> dict:
    """Write a detached signature file (JSON) next to the signed file."""
    import hashlib
    sk = load_or_create_key()
    data = Path(path).read_bytes()
    sig = sk.sign(data).signature
    doc = {
        "file": Path(path).name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(bytes(sk.verify_key)).decode(),
        "signature": base64.b64encode(sig).decode(),
        **(extra or {}),
    }
    Path(sig_path).write_text(json.dumps(doc, indent=2))
    return doc


def verify_file(path: Path, sig_path: Path) -> dict:
    """Return {valid, reason, public_key, fingerprint, sha256}."""
    import hashlib
    path, sig_path = Path(path), Path(sig_path)
    if not sig_path.exists():
        return {"valid": False, "reason": f"No signature file {sig_path.name}"}
    if not path.exists():
        return {"valid": False, "reason": f"Signed file {path.name} is missing"}
    doc = json.loads(sig_path.read_text())
    data = path.read_bytes()
    out = {"public_key": doc.get("public_key"), "fingerprint": fingerprint(doc["public_key"]),
           "sha256": hashlib.sha256(data).hexdigest(), "signed_sha256": doc.get("sha256"),
           "signed_at": doc.get("signed_at")}
    try:
        VerifyKey(base64.b64decode(doc["public_key"])).verify(data, base64.b64decode(doc["signature"]))
        out.update(valid=True, reason="Signature valid")
    except (BadSignatureError, ValueError, KeyError):
        out.update(valid=False, reason="Signature invalid: file changed after signing")
    out["trusted_key"] = doc.get("public_key") == public_key_b64()
    return out
