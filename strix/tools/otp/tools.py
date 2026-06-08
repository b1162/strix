"""``get_totp`` — TOTP code generation for MFA-protected targets.

Wraps pyotp to generate time-based one-time passwords on demand.
Secrets can be supplied as raw Base32 strings or as paths to
SOPS-encrypted files (``sops --decrypt`` is invoked when the path
exists on disk).
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


def _load_secret(secret_or_path: str) -> str:
    """Return the raw Base32 TOTP secret from either a literal or a file path.

    If ``secret_or_path`` is a path that exists on disk, attempt SOPS
    decryption first.  The decrypted payload may be JSON (``{"secret":
    "..."}`` or similar keys) or plain text.  Falls back to reading the
    file as plain text when ``sops`` is not available.
    """
    path = Path(secret_or_path)
    if not path.exists():
        return secret_or_path.strip()

    try:
        result = subprocess.run(  # noqa: S603
            ["sops", "--decrypt", str(path)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            raise RuntimeError(f"sops --decrypt exited {result.returncode}: {result.stderr.strip()}")
        decrypted = result.stdout.strip()
    except FileNotFoundError:
        logger.warning("sops not found; reading secret file as plain text")
        decrypted = path.read_text(encoding="utf-8").strip()

    try:
        parsed = json.loads(decrypted)
    except (json.JSONDecodeError, ValueError):
        return decrypted

    if isinstance(parsed, dict):
        for key in ("secret", "totp_secret", "otp_secret", "seed", "key"):
            if key in parsed:
                return str(parsed[key]).strip()

    return decrypted


def _get_totp_impl(
    secret_or_path: str,
    digits: int,
    period: int,
) -> dict[str, Any]:
    try:
        import pyotp  # noqa: PLC0415
    except ImportError:
        return {
            "success": False,
            "error": "pyotp is not installed — add 'pyotp>=2.9.0' to project dependencies.",
        }

    try:
        secret = _load_secret(secret_or_path)
        totp = pyotp.TOTP(secret, digits=digits, interval=period)
        code = totp.now()
        now = int(time.time())
        valid_until = (now // period + 1) * period
        return {
            "success": True,
            "code": code,
            "valid_until": valid_until,
            "valid_seconds_remaining": valid_until - now,
        }
    except Exception:
        logger.exception("get_totp failed")
        return {"success": False, "error": "Failed to generate TOTP code — check the secret."}


@function_tool(timeout=20)
async def get_totp(
    ctx: RunContextWrapper,
    secret_or_path: str,
    digits: int = 6,
    period: int = 30,
) -> str:
    """Generate a TOTP (Time-based One-Time Password) code for MFA-protected targets.

    Use this whenever a login form or API requires a 2FA / MFA code.
    Returns the current code and exactly how many seconds it stays valid —
    time your request before it expires.

    Secrets can be provided as:
    - A raw Base32 string (e.g. ``"JBSWY3DPEHPK3PXP"``).
    - An absolute path to a SOPS-encrypted file whose decrypted content is
      either a plain Base32 string or a JSON object with a ``secret``
      (or ``totp_secret`` / ``otp_secret`` / ``seed``) key.

    Args:
        secret_or_path: Base32 TOTP secret or path to a SOPS-encrypted secret file.
        digits: OTP length in digits — 6 (default) or 8 for services that use 8-digit codes.
        period: Validity window in seconds — 30 (default) or 60 for longer-lived codes.
    """
    result = await asyncio.to_thread(_get_totp_impl, secret_or_path, digits, period)
    return json.dumps(result, ensure_ascii=False, default=str)
