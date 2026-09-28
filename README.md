# AuditGuard AaaS

AuditGuard is a FastAPI service for PII redaction and prompt-injection defense.

## Live service

- Base URL: https://auditguard-aaas.onrender.com
- Swagger: https://auditguard-aaas.onrender.com/docs
- Health: https://auditguard-aaas.onrender.com/health
- Agent orchestration: `POST /v1/agents/evaluate`
- Plans: `GET /v1/plans`
- Industries: `GET /v1/industries`
- Transparent local benchmark: `GET /v1/benchmark`
- Interactive security audit: `POST /v1/security/audit`
- Free PII playground: `/playground`
- Local leaked-key radar: `POST /v1/security/leaked-key-check`
- Feedback loop: `POST /v1/feedback`
- Payment verification: `POST /v1/verify-payment`
- CFO Binance read-only balance: `GET /v1/cfo/binance/balance`

## SDKs

Publish-ready Python and JavaScript SDK source packages are in [`sdks/`](sdks/). They are intentionally not published to PyPI or npm automatically.

## Safety notes

Payment verification checks BNB Smart Chain receipt status, USDT contract, sender, recipient, amount and confirmations before activation. Binance integration is strictly read-only and requires a restricted API key in `BINANCE_API_KEY`/`BINANCE_API_SECRET`; no withdrawal or transfer endpoint exists. The model failover is optional and requires a user-supplied `GROQ_API_KEY`. External marketing messages, GitHub scans and public benchmark claims are not automated; the leaked-key radar accepts supplied text only.
