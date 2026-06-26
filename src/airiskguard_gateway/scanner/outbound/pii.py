from __future__ import annotations

import re
import uuid

from airiskguard_gateway.models import Category, Finding, Severity


_PII_PATTERNS: list[dict] = [
    {
        "name": "email",
        "pattern": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "severity": Severity.HIGH,
        "title": "Email address in prompt",
        "false_positive_patterns": [
            re.compile(r"example@example\.com", re.IGNORECASE),
            re.compile(r"user@example\.com", re.IGNORECASE),
            re.compile(r"test@test\.com", re.IGNORECASE),
            re.compile(r"noreply@", re.IGNORECASE),
            re.compile(r"no-reply@", re.IGNORECASE),
            re.compile(r"@airiskguard\.ai$", re.IGNORECASE),
        ],
    },
    {
        "name": "us_phone",
        "pattern": re.compile(r"\b(?:\+1[\-.\s]?)?\(?\d{3}\)?[\-.\s]?\d{3}[\-.\s]?\d{4}\b"),
        "severity": Severity.HIGH,
        "title": "US phone number in prompt",
        "false_positive_patterns": [],
    },
    {
        "name": "ssn",
        "pattern": re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
        "severity": Severity.CRITICAL,
        "title": "Social Security Number (SSN) in prompt",
        "false_positive_patterns": [],
    },
    {
        "name": "credit_card",
        "pattern": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        "severity": Severity.CRITICAL,
        "title": "Credit card number in prompt",
        "false_positive_patterns": [],
    },
    {
        "name": "ip_address",
        "pattern": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        "severity": Severity.MEDIUM,
        "title": "IP address in prompt",
        "false_positive_patterns": [
            re.compile(r"^(?:127\.|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)"),
        ],
    },
    {
        "name": "dob",
        "pattern": re.compile(r"\b(?:0?[1-9]|1[0-2])[/\-](0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"),
        "severity": Severity.HIGH,
        "title": "Date of birth pattern in prompt",
        "false_positive_patterns": [],
    },
]


def scan_outbound_pii(text: str, location: str = "outbound_request") -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for p in _PII_PATTERNS:
        matches = list(p["pattern"].finditer(text))
        real_matches = [m for m in matches if not _is_false_positive(m.group(0), p["false_positive_patterns"])]

        if not real_matches:
            continue

        key = f"{p['name']}:{location}"
        if key in seen:
            continue
        seen.add(key)

        examples = [m.group(0)[:6] + "***" for m in real_matches[:3]]
        findings.append(Finding(
            id=str(uuid.uuid4()),
            category=Category.PII_LEAKAGE,
            severity=p["severity"],
            title=p["title"],
            description=f"Found {len(real_matches)} {p['name']} pattern(s) in outbound prompt. Examples: {', '.join(examples)}",
            evidence=f"{len(real_matches)} match(es)",
            location=location,
            remediation=f"Remove {p['name']} data from AI prompts. PII sent to external AI providers may violate GDPR, HIPAA, or CCPA.",
        ))

    return findings


def _is_false_positive(value: str, fp_patterns: list[re.Pattern]) -> bool:
    return any(p.search(value) for p in fp_patterns)
