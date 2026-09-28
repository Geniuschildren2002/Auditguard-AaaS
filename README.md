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

## SDKs

Publish-ready Python and JavaScript SDK source packages are in [`sdks/`](sdks/). They are intentionally not published to PyPI or npm automatically.

## Safety notes

Payment endpoints expose plan metadata only. API keys are not issued from an arbitrary transaction hash; on-chain verification and automatic transfers are not enabled. The model failover is optional and requires a user-supplied `GROQ_API_KEY`. External marketing messages, GitHub scans and public benchmark claims are not automated; the leaked-key radar accepts supplied text only.
