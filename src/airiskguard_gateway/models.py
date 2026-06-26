from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    HARDCODED_SECRETS = "hardcoded_secrets"
    PII_LEAKAGE = "pii_leakage"
    VULNERABLE_CODE = "vulnerable_code"
    MODEL_POLICY = "model_policy"
    PROMPT_INJECTION = "prompt_injection"


@dataclass
class Finding:
    id: str
    category: Category
    severity: Severity
    title: str
    description: str
    evidence: str
    location: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location,
            "remediation": self.remediation,
        }


@dataclass
class PolicyDecision:
    action: Literal["allow", "block", "redact"]
    findings: list[Finding] = field(default_factory=list)
    message: str = ""


# Severity ordering for comparisons
SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
