# ScamShield AI — Presentation Outline

## Slide 1 — Hook / Problem Statement
- 3.4 billion phishing emails sent daily (Statista 2024)
- US elder fraud losses exceeded $3.4 B in 2023 (FBI IC3)
- Most victims only realise after money is gone
- **ScamShield AI: real-time, multi-channel scam interception for everyone**

---

## Slide 2 — What We Built
- **Multi-agent AI system** that analyses calls, emails, and financial messages
- Detects scam patterns _before_ a victim acts
- Alerts a trusted family member / guardian instantly
- 100% offline-capable (no API key required for rule-based mode)

---

## Slide 3 — System Architecture
_(embed architecture diagram from docs/architecture.md)_

Key layers:
1. Security gateway (PII redaction, rate limiting, audit log)
2. MCP Tool Server (4 tools, stdio transport)
3. Agent layer (1 orchestrator + 5 specialists)
4. CLI + webhook ingestion

---

## Slide 4 — The MCP Tool Server
- `analyze_text` — pattern-match against 50+ scam phrases across 5 categories
- `check_url` — Levenshtein typosquatting + TLD heuristics against 30+ trusted domains
- `risk_scorer` — weighted fusion (55% text, 35% URL, channel bonus)
- `notification_tool` — pluggable SMS/email dispatch (Twilio/SendGrid-ready)
- **Connects to Claude Desktop or Cursor** via stdio MCP transport

---

## Slide 5 — Agent Specialization

| Agent | Domain | Key Signals |
|---|---|---|
| `CallProtectionAgent` | Voice/VOIP | Impersonation, urgency, gift cards |
| `PhishingEmailAgent` | Email | Typosquat URLs, credential harvesting |
| `FinancialScamAgent` | Investment | Advance fee, guaranteed returns, crypto |
| `RiskMemoryAgent` | Cross-session | Repeat-offender score boost |
| `FamilyNotificationAgent` | Alerting | Threshold-gated guardian SMS |

---

## Slide 6 — Live Demo
1. `python demo/demo_script.py` — all three scam types, coloured verdicts
2. `scamshield scan --type email --file demo/sample_inputs/phishing_email.txt`
3. `scamshield batch-scan --type email --dir demo/sample_inputs --output report.json`
4. Show `family_notifications.log` — simulated guardian SMS
5. `scamshield verify-audit` — hash-chain verified ✓

---

## Slide 7 — Security Design
- **PII Redaction**: SSN, card numbers, phones, emails scrubbed before any external call
- **Hash-Chained Audit Log**: tamper-evident, SIEM-ready (set `SIEM_WEBHOOK_URL`)
- **Rate Limiting**: sliding-window per user, protects from API abuse
- **HMAC Webhooks**: signed payloads prevent spoofed ingestion
- **Non-root Docker**: minimal attack surface in production

---

## Slide 8 — Google ADK Integration
```python
from agents.guardian_agent import GuardianADKAgent

agent = GuardianADKAgent()         # wraps GuardianAgent as ADK Agent
result = agent.process(
    user_id="alice",
    input_type="email",
    text=email_body,
)
```
- All 4 MCP tools exposed as ADK `FunctionTool` objects
- LLM (Gemini) can plan multi-step analysis, ask clarifying questions
- Falls back to rule-based GuardianAgent when `google-adk` not installed

---

## Slide 9 — Deployment
```bash
# Claude Desktop
# → Add scamshield block to claude_desktop_config.json

# Docker webhook server
docker run -p 8080:8080 scamshield \
  python -m cli.scamshield_cli serve-webhook --type email

# Scheduled batch scan (cron)
scamshield batch-scan --type email --dir /var/mail/inbox --output /reports/daily.json
```

---

## Slide 10 — Results & Next Steps

**Demo results** (rule-based, no API key):
- Scam call transcript → HIGH_RISK_SCAM (91/100)
- Phishing email → HIGH_RISK_SCAM (85/100)
- Fake investment → LIKELY_SCAM (67/100)

**Next steps**:
1. Wire in Gemini / Claude for richer reasoning via ADK
2. Ship logs to Splunk / Datadog SIEM
3. Add voice transcription (Whisper) for live call monitoring
4. Build a Telegram/Slack bot front-end on the webhook endpoint
5. Extend training data with FTC / FBI IC3 reported scam patterns

---

## Appendix — Repository Structure
_(paste the file tree from README.md)_
