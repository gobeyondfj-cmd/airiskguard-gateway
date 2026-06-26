from __future__ import annotations

import re
import uuid

from airiskguard_gateway.models import Category, Finding, Severity


# OWASP Top 10 patterns for code blocks in AI responses
_VULN_CODE_PATTERNS: list[dict] = [
    {
        "name": "sql_injection",
        "pattern": re.compile(
            r'(?:execute|cursor\.execute|db\.query|conn\.execute)\s*\(\s*[f"\'].*?%s|'
            r'SELECT\s+.*?\+\s*(?:user_input|request\.|params\.|query\.|body\.)|'
            r'(?:f"SELECT|f\'SELECT).*?\{',
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": Severity.CRITICAL,
        "title": "Potential SQL injection in generated code",
        "remediation": "Use parameterized queries or an ORM instead of string interpolation.",
    },
    {
        "name": "command_injection",
        "pattern": re.compile(
            r'os\.system\s*\(\s*(?:f["\']|.*?\+)|'
            r'subprocess\.\w+\s*\(\s*(?:f["\']|.*?\+|shell=True.*?(?:input|request|param))|'
            r'eval\s*\(\s*(?:request|input|params|user)',
            re.IGNORECASE,
        ),
        "severity": Severity.CRITICAL,
        "title": "Potential command injection in generated code",
        "remediation": "Use subprocess with a list of arguments (not shell=True) and never pass user input to os.system/eval.",
    },
    {
        "name": "path_traversal",
        "pattern": re.compile(
            r'open\s*\(\s*(?:f["\']|.*?\+).*?(?:request|input|param|user)',
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "title": "Potential path traversal in generated code",
        "remediation": "Validate and sanitize file paths. Use os.path.abspath and check that the resolved path is within an allowed directory.",
    },
    {
        "name": "hardcoded_secret_in_code",
        "pattern": re.compile(
            r'(?:api_key|apikey|secret|password|token)\s*=\s*["\'][A-Za-z0-9\-_]{16,}["\']',
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "title": "Hardcoded secret in generated code",
        "remediation": "Use environment variables or a secrets manager instead of hardcoded credentials.",
    },
    {
        "name": "weak_crypto",
        "pattern": re.compile(
            r'(?:md5|sha1)\s*\(',
            re.IGNORECASE,
        ),
        "severity": Severity.MEDIUM,
        "title": "Weak cryptographic hash in generated code",
        "remediation": "Use SHA-256 or SHA-3 for general hashing; use bcrypt/argon2 for password hashing.",
    },
    {
        "name": "ssrf",
        "pattern": re.compile(
            r'requests\.get\s*\(\s*(?:f["\']|.*?\+|.*?(?:request|input|param|user))|'
            r'httpx\.get\s*\(\s*(?:f["\']|.*?\+|.*?(?:request|input|param|user))',
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "title": "Potential SSRF in generated code",
        "remediation": "Validate and allowlist URLs before making outbound HTTP requests. Never forward user-supplied URLs directly.",
    },
    {
        "name": "insecure_deserialization",
        "pattern": re.compile(
            r'pickle\.loads?\s*\(|'
            r'yaml\.load\s*\([^)]*\)\s*(?!.*Loader)',
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "title": "Insecure deserialization in generated code",
        "remediation": "Use pickle alternatives (json, msgpack) for untrusted data. Use yaml.safe_load instead of yaml.load.",
    },
]

# Match fenced code blocks: ```lang\n...\n```
_CODE_BLOCK_RE = re.compile(r"```(?:[a-z]*)\n(.*?)```", re.DOTALL)


def scan_inbound_vuln_code(text: str, location: str = "inbound_response") -> list[Finding]:
    findings: list[Finding] = []

    # Extract code blocks from the response
    code_blocks = _CODE_BLOCK_RE.findall(text)
    # If no fenced blocks, scan the whole text (might be a raw code response)
    targets = code_blocks if code_blocks else [text]

    seen: set[str] = set()
    for i, block in enumerate(targets):
        block_location = f"{location}:code_block_{i}" if code_blocks else location

        for p in _VULN_CODE_PATTERNS:
            if p["pattern"].search(block):
                key = f"{p['name']}:{i}"
                if key in seen:
                    continue
                seen.add(key)

                match = p["pattern"].search(block)
                evidence = match.group(0)[:100] if match else ""

                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    category=Category.VULNERABLE_CODE,
                    severity=p["severity"],
                    title=p["title"],
                    description=f"AI-generated code contains a {p['name']} pattern.",
                    evidence=evidence,
                    location=block_location,
                    remediation=p["remediation"],
                ))

    return findings
