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

## SDKs

Publish-ready Python and JavaScript SDK source packages are in [`sdks/`](sdks/). They are intentionally not published to PyPI or npm automatically.

## Safety notes

Payment endpoints expose plan metadata only. API keys are not issued from an arbitrary transaction hash; on-chain verification must be implemented before production activation. External marketing messages and public benchmark claims are not automated.
