# AIRiskGuard Gateway

![PyPI](https://img.shields.io/pypi/v/airiskguard-gateway)
![License: MIT](https://img.shields.io/badge/License-MIT-00d4ff.svg)
![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)

AI traffic management for developer teams. A local HTTPS proxy that sits between your developers and AI provider APIs — routing, logging, and protecting every AI call.

**Free (MIT) · `pip install airiskguard` · works with Claude Code, Cursor, Copilot, any AI tool**

## What it does

- **Smart routing** — route PII to an internal model, financial data to Azure, simple queries to cheaper models. Rules in plain YAML.
- **Cost dashboard** — see spend by model, by day, by team. Know your AI bill before it arrives.
- **Secrets + PII protection** — blocks API keys, SSNs, credit cards, and financial data before they reach external APIs.
- **Model allowlist** — define which models your team can use. Everything else is blocked at the proxy.
- **Session stickiness** — conversations stay on the same model. No broken contexts when routing changes.

## Quickstart

```bash
pip install airiskguard
sudo airiskguard-gateway setup    # generate CA cert + print shell config
airiskguard-gateway start
```

`setup` generates the CA certificate, installs it to your system trust store, and prints the exact lines to add to your shell config.

### Claude Code

```bash
# Add to ~/.zshrc or ~/.bashrc
export HTTPS_PROXY=http://127.0.0.1:8080
export NODE_EXTRA_CA_CERTS=~/.config/airiskguard-gateway/mitmproxy-ca-cert.pem
```

Then restart Claude Code. Every AI call is now proxied.

### Cursor

Settings → Features → HTTP Proxy → set to `http://127.0.0.1:8080`

The CA cert must also be trusted — `sudo airiskguard-gateway setup` handles this.

### OpenAI Codex CLI

```bash
export HTTPS_PROXY=http://127.0.0.1:8080
```

Codex CLI respects `HTTPS_PROXY` automatically.

### Any other AI tool

Set `HTTPS_PROXY=http://127.0.0.1:8080`. If the tool uses Node.js, also set `NODE_EXTRA_CA_CERTS`.

### Verify it's working

```bash
airiskguard-gateway start &
# make any AI request in Claude Code or Cursor
airiskguard-gateway logs --tail 5
# you should see the request appear
```

## Configuration

Config lives at `~/.config/airiskguard-gateway/config.yaml`. Generate the default:

```bash
airiskguard-gateway config init
```

Key settings:

```yaml
on_secrets_detected: block    # block | redact | log
on_pii_detected: redact       # block | redact | log

allowed_models:
  - claude-sonnet-4-6
  - gpt-4o
  - deepseek-chat
```

## Smart Routing

Route requests based on content, task type, language, or model:

```yaml
routing:
  sticky_sessions: true      # same conversation → same model
  session_ttl_hours: 24

  rules:
    # PII → never leaves the machine
    - match: contains_pii
      action: route_to
      destination: local_ollama

    # Simple questions → cheap model
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

  destinations:
    local_ollama:
      provider: ollama
      model: llama3.2

    deepseek_cheap:
      provider: deepseek
      model: deepseek-chat    # $0.14/M vs $10/M for GPT-4o

    moonshot:
      provider: moonshot
      model: moonshot-v1-8k

    gpt_mini:
      provider: openai
      model: gpt-4o-mini
```

## Supported Providers

Built-in — just set the env var:

| Provider | Env var | Notes |
|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY` | |
| OpenAI | `OPENAI_API_KEY` | |
| DeepSeek | `DEEPSEEK_API_KEY` | 94% cheaper than GPT-4o |
| Moonshot | `MOONSHOT_API_KEY` | Chinese-optimized |
| GLM (Zhipu) | `GLM_API_KEY` | |
| MiniMax | `MINIMAX_API_KEY` | |
| Mistral | `MISTRAL_API_KEY` | |
| Azure OpenAI | `AZURE_OPENAI_API_KEY` | set `base_url` in config |
| Ollama | none | local models |

Add any OpenAI-compatible provider (vLLM, LiteLLM, etc.):

```yaml
providers:
  my_private_llm:
    base_url: https://llm.internal.company.com/v1
    format: openai
    api_key_env: MY_LLM_API_KEY
```

## CLI Commands

```bash
airiskguard-gateway start              # start proxy (foreground)
airiskguard-gateway start --daemon     # start as background daemon
airiskguard-gateway stop               # stop daemon
airiskguard-gateway status             # show status + last hour stats
airiskguard-gateway logs --tail 50     # view audit log
airiskguard-gateway logs --follow      # live log stream
airiskguard-gateway logs --blocked-only
airiskguard-gateway install-cert       # generate CA + install to OS trust store
airiskguard-gateway config init        # write default config.yaml
```

## Team Tier ($299/mo)

The free proxy runs locally. The Team tier adds:

- Web dashboard with cost breakdown by model
- Centralized policy server for all developer machines
- Slack alerts on blocked requests
- Per-team policies and model allowlists
- 30-day audit log retention

Start at [airiskguard.ai](https://airiskguard.ai/#pricing).

## License

Proxy core: **MIT** — free to use, modify, and distribute.
Policy server + dashboard (`src/airiskguard_gateway/policy_server/`): **Proprietary** — requires a Team license. See [airiskguard.ai/pricing](https://airiskguard.ai/#pricing).
