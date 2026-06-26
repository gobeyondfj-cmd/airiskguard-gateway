from __future__ import annotations

import re
import uuid
from typing import Iterator

from airiskguard_gateway.models import Category, Finding, Severity


# Patterns adapted from airiskguard-scan's SECRET_PATTERNS for text scanning
_SECRET_PATTERNS: list[dict] = [
    {
        "name": "anthropic_api_key",
        "pattern": re.compile(r"sk-ant-(?:api03|admin01)-[A-Za-z0-9\-_]{40,}", re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "title": "Anthropic API key in prompt",
        "remediation": "Remove the API key from the prompt. Use environment variables instead.",
    },
    {
        "name": "openai_api_key",
        "pattern": re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}", re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "title": "OpenAI API key in prompt",
        "remediation": "Remove the API key from the prompt. Use environment variables instead.",
    },
    {
        "name": "generic_api_key",
        "pattern": re.compile(r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?', re.IGNORECASE),
        "severity": Severity.HIGH,
        "title": "Generic API key or secret in prompt",
        "remediation": "Remove credentials from prompts. Reference secrets by name only.",
    },
    {
        "name": "private_key",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "severity": Severity.CRITICAL,
        "title": "Private key material in prompt",
        "remediation": "Never include private keys in AI prompts. Use a secrets manager.",
    },
    {
        "name": "db_connection_string",
        "pattern": re.compile(r"(?:postgresql|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s\"']+", re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "title": "Database connection string with credentials in prompt",
        "remediation": "Remove the connection string. Reference database config from environment.",
    },
    {
        "name": "aws_access_key",
        "pattern": re.compile(r"(?:AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}"),
        "severity": Severity.CRITICAL,
        "title": "AWS access key in prompt",
        "remediation": "Remove the AWS key. Use IAM roles or environment variables.",
    },
    {
        "name": "github_token",
        "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}", re.IGNORECASE),
        "severity": Severity.HIGH,
        "title": "GitHub token in prompt",
        "remediation": "Remove the token. Use short-lived tokens scoped to minimum permissions.",
    },
    {
        "name": "password_in_prompt",
        "pattern": re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?', re.IGNORECASE),
        "severity": Severity.HIGH,
        "title": "Password in prompt",
        "remediation": "Never include passwords in AI prompts.",
    },
]


def scan_outbound_secrets(text: str, location: str = "outbound_request") -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for p in _SECRET_PATTERNS:
        for match in p["pattern"].finditer(text):
            key = f"{p['name']}:{match.start()}"
            if key in seen:
                continue
            seen.add(key)

            evidence = _redact_match(text, match)
            findings.append(Finding(
                id=str(uuid.uuid4()),
                category=Category.HARDCODED_SECRETS,
                severity=p["severity"],
                title=p["title"],
                description=f"Detected {p['name']} pattern in outbound prompt text.",
                evidence=evidence,
                location=location,
                remediation=p["remediation"],
            ))

    return findings


def redact_secrets(text: str) -> str:
    result = text
    for p in _SECRET_PATTERNS:
        result = p["pattern"].sub("[REDACTED]", result)
    return result


def _redact_match(text: str, match: re.Match) -> str:
    start = max(0, match.start() - 20)
    end = min(len(text), match.end() + 20)
    snippet = text[start:end]
    # Replace the actual secret value with asterisks
    secret = match.group(0)
    redacted = secret[:4] + "*" * (len(secret) - 4)
    return snippet.replace(secret, redacted)
