# ScamShield AI — Architecture

## Overview

ScamShield AI is a multi-agent scam protection system that analyses inbound
communications (phone calls, emails, financial messages) for fraud indicators
and alerts a designated guardian contact when a high-risk scam is detected.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Clients / Interfaces                     │
│  CLI  ·  Webhook HTTP server  ·  Claude Desktop (MCP)  ·  ADK  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Security Gateway                             │
│  InputSanitizer (PII redaction + injection detection)          │
│  RateLimiter (sliding-window per user_id)                      │
│  AuditLogger (hash-chained + SIEM webhook)                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     GuardianAgent (orchestrator)                │
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────┐  │
│  │CallProtectionAgent│  │PhishingEmailAgent│  │FinancialScam│  │
│  │                  │  │                  │  │   Agent     │  │
│  └────────┬─────────┘  └────────┬─────────┘  └──────┬──────┘  │
│           │                     │                    │         │
│           └─────────────────────┴────────────────────┘         │
│                                 │                               │
│                    ┌────────────▼────────────┐                  │
│                    │   RiskMemoryAgent        │                  │
│                    │ (per-user rolling hist.) │                  │
│                    └────────────┬────────────┘                  │
│                                 │                               │
│                    ┌────────────▼────────────┐                  │
│                    │ FamilyNotificationAgent  │                  │
│                    └─────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                  MCP Tool Server                                │
│                                                                 │
│  analyze_text   check_url   risk_scorer   notification_tool    │
│                                                                 │
│  Resources: scam_patterns.json · legitimate_domains.json       │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### Security Layer (`security/`)

| Module | Purpose |
|---|---|
| `input_sanitizer.py` | Strip control chars, detect prompt injection, redact PII (SSN, card, phone, email) |
| `rate_limiter.py` | Sliding-window per-user rate limit (default 30 calls/60 s) |
| `audit_logger.py` | SHA-256 hash-chained append-only log with optional SIEM webhook |

### MCP Tool Server (`mcp_server/`)

The server exposes four tools via the Model Context Protocol (stdio transport):

| Tool | Input | Output |
|---|---|---|
| `analyze_text` | `text: str` | `matched_categories`, `raw_text_score` |
| `check_url` | `url: str` | `is_typosquat_suspect`, `flags`, `url_risk_score` |
| `risk_scorer` | text_result, url_results, channel_hint | `final_score`, `verdict` |
| `notification_tool` | recipient, message, severity, channel | delivery receipt |

**Transport**: `python -m mcp_server.server` starts the stdio MCP server. Add it to your `claude_desktop_config.json` or Cursor settings to use it directly from an AI assistant.

### Agent Layer (`agents/`)

```
GuardianAgent
├── CallProtectionAgent   — voice/call transcript analysis
├── PhishingEmailAgent    — email body + URL + sender domain analysis
├── FinancialScamAgent    — investment/crypto/advance-fee fraud patterns
├── RiskMemoryAgent       — per-user rolling history, repeat-offender boost
└── FamilyNotificationAgent — threshold-gated guardian alert
```

**Google ADK integration**: `GuardianADKAgent` (in `guardian_agent.py`) wraps GuardianAgent as a `google.adk.agents.Agent`, exposing all four MCP tools as ADK `FunctionTool` objects for LLM-driven planning loops.

### CLI (`cli/scamshield_cli.py`)

```
scamshield scan         — single-item scan
scamshield batch-scan   — scan a directory, produce JSON report
scamshield export       — dump audit log as JSON or CSV
scamshield verify-audit — verify hash-chain integrity
scamshield serve-webhook — HMAC-secured HTTP webhook endpoint
```

## Risk Scoring Formula

```
combined_score = round(0.55 × text_score + 0.35 × url_score + channel_weight)

Verdict thresholds:
  ≥ 80 → HIGH_RISK_SCAM
  ≥ 60 → LIKELY_SCAM
  ≥ 30 → SUSPICIOUS
  <  30 → LIKELY_SAFE

Repeat-offender boost:
  3+ high-risk hits in last 5 → +15 pts
  1-2 high-risk hits           → +5  pts
```

## Deployment Options

### Option A — Claude Desktop / Cursor (local MCP)

```json
{
  "mcpServers": {
    "scamshield": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/path/to/scamshield-ai"
    }
  }
}
```

### Option B — Docker (webhook server)

```bash
docker build -t scamshield .
docker run -e WEBHOOK_SECRET=mysecret -p 8080:8080 scamshield \
  python -m cli.scamshield_cli serve-webhook --type email --port 8080
```

### Option C — Scheduled batch job (cron)

```bash
0 6 * * * cd /app && python -m cli.scamshield_cli \
  batch-scan --type email --dir /var/mail/inbox --output /reports/daily.json
```

## Security Considerations

- **PII is redacted** before any text leaves the local system (in `redacted_text`).
- **Rate limiting** prevents resource exhaustion and brute-force probing.
- **Hash chaining** in the audit log detects any post-hoc deletion or modification.
- **HMAC signatures** on webhook payloads prevent spoofed scam submissions.
- **Non-root Docker image** reduces container breakout risk.
- **SIEM shipping** is fire-and-forget so it cannot block the analysis pipeline.
