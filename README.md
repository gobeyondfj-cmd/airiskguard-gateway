# AIRiskGuard Gateway

![PyPI](https://img.shields.io/pypi/v/airiskguard)
![License: MIT](https://img.shields.io/badge/License-MIT-00d4ff.svg)
![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)

AI traffic management for developer teams. A local proxy that sits between your developers and AI provider APIs — routing, logging, and protecting every AI call.

**Free (MIT) · `pip install airiskguard` · works with Claude Code, Cursor, Copilot, any AI tool**

## What it does

- **Smart routing** — route PII to an internal model, financial data to Azure, simple queries to cheaper models. Rules in plain YAML. Session stickiness keeps conversations on the same model.
- **Cost dashboard** — see spend by model, by day, by team. Know your AI bill before it arrives.
- **Sensitive data protection** — blocks API keys, SSNs, credit cards, and financial data before they reach external APIs. Redacts or blocks based on your policy.
- **Model allowlist** — define which models your team can use. Everything else is blocked.
- **Content classification** — detects task type (code, summarization, translation, Q&A), complexity, and language to enable smarter routing rules.

---

## Quickstart

```bash
pip install airiskguard
airiskguard-gateway start         # starts API proxy on localhost:8080
```

### Configure your AI tool

**Claude Code** — set `ANTHROPIC_BASE_URL`:
```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080/anthropic
```

**OpenAI Codex CLI** — set `OPENAI_BASE_URL`:
```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/openai
```

**DeepSeek / Moonshot / GLM / any provider:**
```bash
export OPENAI_BASE_URL=http://127.0.0.1:8080/deepseek   # or /moonshot, /glm, /minimax
```

**Cursor** — use transparent proxy mode:
```bash
airiskguard-gateway start --mode proxy
# then: Settings → Features → HTTP Proxy → http://127.0.0.1:8080
```

### Verify it's working

```bash
# In another terminal, after setting the env var above:
airiskguard-gateway logs --tail 5
# You should see your AI requests appear here
```

---

## API Keys

Check which keys are configured:

```bash
airiskguard-gateway keys
```

```
Provider       Env Var                  Status      Key (masked)
anthropic      ANTHROPIC_API_KEY        ✓ env       sk-ant-...
openai         OPENAI_API_KEY           ✗ missing
deepseek       DEEPSEEK_API_KEY         ✓ config    sk-...
ollama         (none)                   n/a         local model
```

**Option 1 — env vars (recommended):**
```bash
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...
export DEEPSEEK_API_KEY=sk-...
export MOONSHOT_API_KEY=sk-...
export GLM_API_KEY=...
export MISTRAL_API_KEY=sk-...
```

**Option 2 — inline in `config.yaml`** (env var takes priority if both set):
```yaml
api_keys:
  anthropic: sk-ant-...
  openai: sk-...
  deepseek: sk-...
  moonshot: sk-...
```

---

## Two modes

| Mode | How it works | Best for |
|---|---|---|
| `api` (default) | FastAPI HTTP server at `localhost:8080`. Point SDKs at it via `BASE_URL`. No CA cert needed. | Claude Code, Codex CLI, any SDK-based tool |
| `proxy` | mitmproxy transparent HTTPS proxy. Set `HTTPS_PROXY`. Requires CA cert install. | Cursor, browser-based tools, generic HTTP clients |

```bash
airiskguard-gateway start              # API mode (default)
airiskguard-gateway start --mode proxy # Transparent proxy mode
```

---

## Configuration

```bash
airiskguard-gateway config init   # write default config to ~/.config/airiskguard-gateway/config.yaml
```

Key settings:

```yaml
on_secrets_detected: block    # block | redact | log
on_pii_detected: redact       # block | redact | log

allowed_models:
  - claude-sonnet-4-6
  - gpt-4o
  - gpt-4o-mini
  - deepseek-chat
```

---

## Smart Routing

Rules are evaluated in order. First match wins. Session stickiness keeps a conversation on the same model once routed.

```yaml
routing:
  sticky_sessions: true       # same conversation → same model
  session_ttl_hours: 24

  rules:
    # PII → local model, never leaves the machine
    - match: contains_pii
      action: route_to
      destination: local_ollama

    # Simple questions → 94% cheaper
    - match: task_type
      task_type: simple_qa
      action: route_to
      destination: deepseek_cheap

    # Chinese prompts → Chinese-optimized model
    - match: language
      language: zh
      action: route_to
      destination: moonshot

    # Downgrade all GPT-4 requests
    - match: model_pattern
      model_pattern: "gpt-4*"
      action: route_to
      destination: gpt_mini

    # Financial data → block external, or route to private endpoint
    - match: contains_financial_data
      action: block

  destinations:
    local_ollama:
      provider: ollama
      model: llama3.2

    deepseek_cheap:
      provider: deepseek
      model: deepseek-chat    # $0.14/M input vs $2.50/M for GPT-4o

    moonshot:
      provider: moonshot
      model: moonshot-v1-8k

    gpt_mini:
      provider: openai
      model: gpt-4o-mini
```

### Available match types

| match | description |
|---|---|
| `contains_pii` | email, phone, SSN, credit card, DOB detected in prompt |
| `contains_secrets` | API keys, DB URIs, private keys detected |
| `contains_financial_data` | revenue, IBAN, account numbers, trade data etc. |
| `task_type` | `simple_qa`, `code_generation`, `summarization`, `translation`, `complex_reasoning`, `data_analysis` |
| `complexity` | `low`, `medium`, `high` — based on prompt length + task type |
| `language` | `zh`, `en`, `ja`, `ko` etc. — detected from character sets |
| `model_pattern` | glob match on requested model name e.g. `gpt-4*` |
| `provider` | match by provider name e.g. `openai`, `anthropic` |
| `always` | catch-all fallback rule |

---

## Supported Providers

Built-in — just set the env var and route to the provider name:

| Provider | Env var | BASE_URL path | Notes |
|---|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY` | `/anthropic` | Claude Code default |
| OpenAI | `OPENAI_API_KEY` | `/openai` | Codex CLI default |
| DeepSeek | `DEEPSEEK_API_KEY` | `/deepseek` | 94% cheaper than GPT-4o |
| Moonshot | `MOONSHOT_API_KEY` | `/moonshot` | Chinese-optimized |
| GLM (Zhipu) | `GLM_API_KEY` | `/glm` | |
| MiniMax | `MINIMAX_API_KEY` | `/minimax` | |
| Mistral | `MISTRAL_API_KEY` | `/mistral` | |
| Azure OpenAI | `AZURE_OPENAI_API_KEY` | `/azure_openai` | set `base_url` in config |
| Google | `GOOGLE_API_KEY` | `/google` | |
| Ollama | (none) | `/ollama` | local models |

Add any OpenAI-compatible provider (vLLM, LiteLLM, custom):

```yaml
providers:
  my_private_llm:
    base_url: https://llm.internal.company.com/v1
    format: openai
    api_key_env: MY_LLM_API_KEY
```

---

## CLI Reference

```bash
airiskguard-gateway setup              # first-time setup: cert + per-tool instructions
airiskguard-gateway start              # start in API mode (default)
airiskguard-gateway start --mode proxy # start in transparent proxy mode
airiskguard-gateway start --daemon     # start as background daemon
airiskguard-gateway stop               # stop daemon
airiskguard-gateway status             # show status + last hour stats
airiskguard-gateway keys               # show API key status for all providers
airiskguard-gateway logs --tail 50     # view audit log
airiskguard-gateway logs --follow      # live stream
airiskguard-gateway logs --blocked-only
airiskguard-gateway license YOUR-KEY   # validate a license key
airiskguard-gateway config init        # write default config.yaml
airiskguard-gateway config show        # print current config
airiskguard-gateway install-cert       # generate CA + install to trust store (proxy mode)
```

---

## Team Tier ($299/mo)

The free proxy runs locally. The Team tier adds:

- Web dashboard with cost breakdown by model
- Centralized policy server — push policies to all developer machines
- Slack alerts on blocked requests
- Per-team model allowlists
- 30-day audit log retention

Start at [airiskguard.ai](https://airiskguard.ai/#pricing).

### Activating your license

```bash
# Validate your key
airiskguard-gateway license YOUR-LICENSE-KEY

# Start the policy server
AIRISKGUARD_LICENSE=YOUR-LICENSE-KEY docker compose up -d
```

---

## License

Proxy core: **MIT** — free to use, modify, and distribute.
Policy server + dashboard (`src/airiskguard_gateway/policy_server/`): **Proprietary** — requires a Team license.
