from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from airiskguard_gateway.config import GatewayConfig, ProviderConfig


@dataclass
class RequestContext:
    provider_name: str          # e.g. "anthropic", "deepseek", "my_custom"
    provider_format: str        # "openai" | "anthropic" | "ollama"
    model: str
    prompt_text: str
    host: str
    path: str
    request_id: str


@dataclass
class ResponseContext:
    provider_name: str
    provider_format: str
    model: str
    response_text: str
    is_streaming: bool


def detect_provider_by_host(host: str, providers: dict[str, "ProviderConfig"]) -> tuple[str, "ProviderConfig"] | tuple[None, None]:
    """Return (name, config) for the provider matching this host, or (None, None)."""
    for name, cfg in providers.items():
        if cfg.host() and (host == cfg.host() or host.endswith("." + cfg.host())):
            return name, cfg
    return None, None


def extract_request_context(
    host: str,
    path: str,
    body: dict[str, Any],
    request_id: str,
    providers: dict[str, "ProviderConfig"],
) -> RequestContext:
    name, cfg = detect_provider_by_host(host, providers)
    fmt = cfg.format if cfg else "openai"
    provider_name = name or "unknown"

    model = body.get("model", "unknown")
    prompt_text = _extract_prompt(fmt, body)

    return RequestContext(
        provider_name=provider_name,
        provider_format=fmt,
        model=model,
        prompt_text=prompt_text,
        host=host,
        path=path,
        request_id=request_id,
    )


def extract_response_text(fmt: str, body: dict[str, Any]) -> str:
    if fmt == "anthropic":
        for block in body.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                return block.get("text", "")
    elif fmt == "ollama":
        msg = body.get("message", {})
        return msg.get("content", "") if isinstance(msg, dict) else ""
    else:
        # openai-compatible (covers openai, deepseek, moonshot, glm, minimax, mistral, etc.)
        choices = body.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            return msg.get("content", "") or ""
    return str(body)


def extract_token_counts(fmt: str, body: dict[str, Any]) -> tuple[int, int]:
    usage = body.get("usage", {})
    if fmt == "anthropic":
        return usage.get("input_tokens", 0), usage.get("output_tokens", 0)
    else:
        # openai-compatible and ollama
        inp = usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0)
        out = usage.get("completion_tokens", 0) or usage.get("output_tokens", 0)
        return inp, out


def extract_sse_token_counts(raw: str, fmt: str) -> tuple[int, int]:
    import json
    for line in reversed(raw.splitlines()):
        if not line.startswith("data:"):
            continue
        data_str = line[5:].strip()
        if data_str in ("[DONE]", ""):
            continue
        try:
            chunk = json.loads(data_str)
            usage = chunk.get("usage", {})
            if fmt == "anthropic":
                inp = usage.get("input_tokens", 0)
                out = usage.get("output_tokens", 0)
            else:
                inp = usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0)
                out = usage.get("completion_tokens", 0) or usage.get("output_tokens", 0)
            if inp or out:
                return inp, out
        except (ValueError, KeyError):
            continue
    return 0, 0


def get_chat_path(fmt: str) -> str:
    """Return the chat completion path for a given provider format."""
    if fmt == "anthropic":
        return "/v1/messages"
    if fmt == "ollama":
        return "/api/chat"
    return "/v1/chat/completions"


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _extract_prompt(fmt: str, body: dict[str, Any]) -> str:
    parts: list[str] = []

    if fmt == "anthropic":
        if system := body.get("system"):
            parts.append(str(system))
        for msg in body.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))

    elif fmt == "ollama":
        # Ollama uses messages array same as OpenAI, or a single "prompt" field
        for msg in body.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
        if prompt := body.get("prompt"):
            parts.append(str(prompt))

    else:
        # openai-compatible: covers openai, deepseek, moonshot, glm, minimax, mistral, azure, google
        for msg in body.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
        if prompt := body.get("prompt"):
            parts.append(str(prompt))

    return "\n".join(parts)
