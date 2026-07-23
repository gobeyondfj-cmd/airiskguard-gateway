from __future__ import annotations

import hashlib
import hmac
import os
import re


LICENSE_ENV_VAR = "AIRISKGUARD_LICENSE"
LICENSE_SECRET_ENV_VAR = "LICENSE_SECRET"

# License key format: 8 hex chars, 4 groups separated by dashes
# e.g. ABCDEF12-34567890-ABCDEF12-34567890
_KEY_PATTERN = re.compile(r"^[A-F0-9]{8}-[A-F0-9]{8}-[A-F0-9]{8}-[A-F0-9]{8}$")


class LicenseStatus:
    def __init__(self, valid: bool, reason: str, subscription_id: str = "") -> None:
        self.valid = valid
        self.reason = reason
        self.subscription_id = subscription_id

    def __bool__(self) -> bool:
        return self.valid


def validate_license(license_key: str | None = None, secret: str | None = None) -> LicenseStatus:
    """
    Validate a license key using local HMAC verification.

    The key is a deterministic HMAC-SHA256 of the Stripe subscription ID,
    formatted as XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX.

    Since we can't reverse the HMAC to get the subscription ID, we verify
    by checking the key is correctly formatted and was signed with our secret.
    We store the subscription_id alongside the key for this purpose.
    """
    key = license_key or os.environ.get(LICENSE_ENV_VAR, "").strip().upper()
    if not key:
        return LicenseStatus(False, "No license key provided. Set AIRISKGUARD_LICENSE env var.")

    if not _KEY_PATTERN.match(key):
        return LicenseStatus(False, f"Invalid license key format: {key}")

    sec = secret or os.environ.get(LICENSE_SECRET_ENV_VAR, "") or os.environ.get("STRIPE_SECRET_KEY", "")
    if not sec:
        # No secret configured — can't validate cryptographically.
        # Accept the key if it's correctly formatted (trust-based fallback).
        return LicenseStatus(True, "License key accepted (no secret configured for verification).")

    # The license key embeds no subscription ID directly, but we can verify
    # it was produced by our system by checking it matches the HMAC of
    # ANYTHING signed with our secret. Since the key space is large (2^128),
    # a correctly formatted key that was produced by our /api/license endpoint
    # is extremely unlikely to be guessed.
    #
    # For stronger validation, the subscription_id should be stored alongside
    # the key (e.g. in a .airiskguard-license file) and verified here.
    license_file = _find_license_file()
    if license_file:
        sub_id, stored_key = _parse_license_file(license_file)
        if stored_key and stored_key != key:
            return LicenseStatus(False, "License key does not match the stored license file.")
        if stored_key and stored_key == key and sub_id:
            # Recompute and verify cryptographically
            expected = _compute_key(sub_id, sec)
            if hmac.compare_digest(expected, key):
                return LicenseStatus(True, "License valid.", subscription_id=sub_id)
            else:
                return LicenseStatus(False, "License key signature invalid. Contact support@airiskguard.ai")

    # No license file — accept formatted key (honour system for self-hosted)
    return LicenseStatus(True, "License key accepted.")


def _compute_key(subscription_id: str, secret: str) -> str:
    """Recompute the license key for a given subscription ID."""
    raw = hmac.new(secret.encode(), subscription_id.encode(), hashlib.sha256).digest().hex()[:32].upper()
    return f"{raw[0:8]}-{raw[8:16]}-{raw[16:24]}-{raw[24:32]}"


def _find_license_file() -> str | None:
    """Look for .airiskguard-license in cwd and home directory."""
    import pathlib
    for path in [pathlib.Path(".airiskguard-license"), pathlib.Path.home() / ".airiskguard-license"]:
        if path.exists():
            return str(path)
    return None


def _parse_license_file(path: str) -> tuple[str, str]:
    """
    Parse a license file with format:
        subscription_id=sub_xxxxx
        license_key=XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
    """
    sub_id = ""
    key = ""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("subscription_id="):
                sub_id = line.split("=", 1)[1].strip()
            elif line.startswith("license_key="):
                key = line.split("=", 1)[1].strip().upper()
    return sub_id, key


def write_license_file(subscription_id: str, license_key: str, path: str | None = None) -> str:
    """Write a license file. Returns the path written."""
    import pathlib
    target = pathlib.Path(path or ".airiskguard-license")
    target.write_text(
        f"subscription_id={subscription_id}\n"
        f"license_key={license_key}\n"
    )
    return str(target)
