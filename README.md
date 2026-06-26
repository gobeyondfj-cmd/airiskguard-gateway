# AIRiskGuard Gateway

AI governance proxy for regulated industries. Sits between your developers and AI provider APIs — logging, enforcing policy, and generating the audit trail your risk and compliance teams need.

## Quickstart

```bash
pip install airiskguard-gateway
airiskguard-gateway install-cert
airiskguard-gateway start
```

Then in your shell:
```bash
export HTTPS_PROXY=http://127.0.0.1:8080
export NODE_EXTRA_CA_CERTS=~/.config/airiskguard-gateway/mitmproxy-ca-cert.pem
```

All AI API calls from Claude Code, Cursor, and other AI tools are now proxied, scanned, and logged.

## Documentation

https://docs.airiskguard.ai/gateway
