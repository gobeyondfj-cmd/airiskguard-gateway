from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Literal


class TaskType(str, Enum):
    CODE_GENERATION = "code_generation"
    SUMMARIZATION = "summarization"
    TRANSLATION = "translation"
    SIMPLE_QA = "simple_qa"
    COMPLEX_REASONING = "complex_reasoning"
    DATA_ANALYSIS = "data_analysis"
    GENERAL = "general"


class Complexity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ContentSignals:
    task_type: TaskType
    complexity: Complexity
    language: str           # "en", "zh", "ja", "ko", "es", "fr", etc.
    estimated_tokens: int
    has_code: bool


# ── Keyword sets ──────────────────────────────────────────────────────────────

_CODE_KEYWORDS = frozenset([
    "write", "implement", "code", "function", "class", "method", "debug",
    "fix", "refactor", "test", "unit test", "script", "program", "algorithm",
    "def ", "class ", "import ", "return ", "async ", "await ",
    "```", "def(", "function(", "const ", "let ", "var ",
    # Chinese code keywords
    "函数", "代码", "脚本", "程序", "算法", "实现", "修复", "重构", "排序", "编写",
])

_SUMMARIZE_KEYWORDS = frozenset([
    "summarize", "summary", "tldr", "tl;dr", "key points", "main points",
    "brief", "overview", "recap", "shorten", "condense",
])

_TRANSLATE_KEYWORDS = frozenset([
    "translate", "translation", "in chinese", "in english", "in japanese",
    "in french", "in spanish", "in korean", "用中文", "翻译", "英文",
])

_REASONING_KEYWORDS = frozenset([
    "analyze", "analysis", "compare", "contrast", "evaluate", "critique",
    "explain why", "reason", "argue", "pros and cons", "trade-off",
    "implications", "consequences", "deep dive", "thorough", "comprehensive",
    "step by step", "architecture", "design", "strategy", "research",
])

_DATA_KEYWORDS = frozenset([
    "calculate", "compute", "statistics", "data", "dataset", "table",
    "spreadsheet", "csv", "sql", "query", "aggregate", "average", "median",
    "correlation", "regression", "chart", "graph", "plot", "visualize",
])

_SIMPLE_PATTERNS = [
    re.compile(r"^(what is|what are|who is|when did|where is|how many|define)\b", re.IGNORECASE),
    re.compile(r"^(yes or no|is it|does it|can you|please (explain|tell me))\b", re.IGNORECASE),
]

# Chinese character range
_ZH_RE = re.compile(r"[一-鿿㐀-䶿]")
_JA_RE = re.compile(r"[぀-ゟ゠-ヿ]")  # hiragana + katakana
_KO_RE = re.compile(r"[가-힯]")


def classify(prompt: str) -> ContentSignals:
    lower = prompt.lower()
    tokens = max(1, len(prompt) // 4)

    # Language detection — check character sets first
    zh_count = len(_ZH_RE.findall(prompt))
    ja_count = len(_JA_RE.findall(prompt))
    ko_count = len(_KO_RE.findall(prompt))
    total_chars = max(1, len(prompt))

    if zh_count / total_chars > 0.1:
        lang = "zh"
    elif ja_count / total_chars > 0.1:
        lang = "ja"
    elif ko_count / total_chars > 0.1:
        lang = "ko"
    else:
        lang = "en"

    has_code = "```" in prompt or any(kw in lower for kw in ["def ", "class ", "import ", "function(", "const "])

    # Task type — order matters, most specific first
    if any(kw in lower for kw in _TRANSLATE_KEYWORDS):
        task_type = TaskType.TRANSLATION
    elif any(kw in lower for kw in _SUMMARIZE_KEYWORDS):
        task_type = TaskType.SUMMARIZATION
    elif has_code or any(kw in lower for kw in _CODE_KEYWORDS):
        task_type = TaskType.CODE_GENERATION
    elif any(kw in lower for kw in _DATA_KEYWORDS):
        task_type = TaskType.DATA_ANALYSIS
    elif any(kw in lower for kw in _REASONING_KEYWORDS) or tokens > 400:
        task_type = TaskType.COMPLEX_REASONING
    elif tokens < 80 and any(p.match(lower.strip()) for p in _SIMPLE_PATTERNS):
        task_type = TaskType.SIMPLE_QA
    else:
        task_type = TaskType.GENERAL

    # Complexity score
    if tokens < 80 and task_type in (TaskType.SIMPLE_QA, TaskType.TRANSLATION, TaskType.SUMMARIZATION):
        complexity = Complexity.LOW
    elif tokens > 500 or task_type in (TaskType.COMPLEX_REASONING, TaskType.DATA_ANALYSIS):
        complexity = Complexity.HIGH
    else:
        complexity = Complexity.MEDIUM

    return ContentSignals(
        task_type=task_type,
        complexity=complexity,
        language=lang,
        estimated_tokens=tokens,
        has_code=has_code,
    )
