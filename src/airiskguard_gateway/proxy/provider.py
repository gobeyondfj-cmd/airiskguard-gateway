from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Provider(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"
    GOOGLE = "google"
    UNKNOWN = "unknown"


@dataclass
class RequestContext:
    provider: Provider
    model: str
    prompt_text: str
    host: str
    path: str
    request_id: str


@dataclass
class ResponseContext:
    provider: Provider
    model: str
    response_text: str
    is_streaming: bool


_PROVIDER_HOST_MAP: list[tuple[re.Pattern, Provider]] = [
    (re.compile(r"api\.anthropic\.com$"), Provider.ANTHROPIC),
    (re.compile(r"api\.openai\.com$"), Provider.OPENAI),
    (re.compile(r".*\.openai\.azure\.com$"), Provider.AZURE_OPENAI),
    (re.compile(r"generativelanguage\.googleapis\.com$"), Provider.GOOGLE),
]


def detect_provider(host: str) -> Provider:
    for pattern, provider in _PROVIDER_HOST_MAP:
        if pattern.match(host):
            return provider
    return Provider.UNKNOWN


def extract_request_context(host: str, path: str, body: dict[str, Any], request_id: str) -> RequestContext:
    provider = detect_provider(host)
    model = body.get("model", "unknown")
    prompt_text = _extract_prompt_text(provider, body)
    return RequestContext(
        provider=provider,
        model=model,
        prompt_text=prompt_text,
        host=host,
        path=path,
        request_id=request_id,
    )


def extract_response_context(provider: Provider, model: str, body: dict[str, Any], is_streaming: bool) -> ResponseContext:
    text = _extract_response_text(provider, body)
    return ResponseContext(provider=provider, model=model, response_text=text, is_streaming=is_streaming)


def _extract_prompt_text(provider: Provider, body: dict[str, Any]) -> str:
    parts: list[str] = []

    if provider == Provider.ANTHROPIC:
        # System prompt
        if system := body.get("system"):
            parts.append(str(system))
        # Messages array
        for msg in body.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))

    elif provider in (Provider.OPENAI, Provider.AZURE_OPENAI):
        for msg in body.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
        # Legacy prompt field
        if prompt := body.get("prompt"):
            parts.append(str(prompt))

    else:
        # Generic fallback: grab any string-valued fields
        for key in ("prompt", "input", "query", "message", "text"):
            if val := body.get(key):
                parts.append(str(val))

    return "\n".join(parts)


def _extract_response_text(provider: Provider, body: dict[str, Any]) -> str:
    if provider == Provider.ANTHROPIC:
        for block in body.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                return block.get("text", "")

    elif provider in (Provider.OPENAI, Provider.AZURE_OPENAI):
        choices = body.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            return msg.get("content", "") or ""

    return str(body)


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)
