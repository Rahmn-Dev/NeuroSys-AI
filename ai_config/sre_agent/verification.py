"""Evidence-first postcondition contracts for safe mutations."""
from __future__ import annotations
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Callable, Any


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    verifier: str
    evidence: dict
    reason: str = ""


def verify_file_readback(path: str, expected_content: str | None = None, expected_sha256: str | None = None) -> VerificationResult:
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        return VerificationResult(False, "file_readback", {"path": path}, str(exc))
    digest = hashlib.sha256(data).hexdigest()
    content_ok = expected_content is None or data.decode("utf-8") == expected_content
    hash_ok = expected_sha256 is None or digest == expected_sha256
    return VerificationResult(content_ok and hash_ok, "file_readback", {"path": path, "sha256": digest}, "readback matched" if content_ok and hash_ok else "readback mismatch")


def verify_config_fixture(path: str, parser: Callable[[str], Any] = json.loads) -> VerificationResult:
    try:
        with open(path, encoding="utf-8") as handle:
            parsed = parser(handle.read())
        return VerificationResult(True, "config_syntax", {"path": path, "type": type(parsed).__name__}, "syntax parsed")
    except Exception as exc:
        return VerificationResult(False, "config_syntax", {"path": path}, str(exc)[:300])


def require_verification(result: VerificationResult) -> dict:
    if not result.verified:
        raise RuntimeError(f"mutation verification failed: {result.reason}")
    return {"verifier": result.verifier, "evidence": result.evidence}
