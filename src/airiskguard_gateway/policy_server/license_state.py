from __future__ import annotations

from airiskguard_gateway.license import LicenseStatus

# Module-level license status set at startup by main.py
_license: LicenseStatus | None = None


def set_license(status: LicenseStatus) -> None:
    global _license
    _license = status


def get_license() -> LicenseStatus:
    return _license or LicenseStatus(False, "License not checked yet.")
