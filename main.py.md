# `main.py`

```python
import hashlib
import os
import re
import sqlite3
import threading
import time
import uuid
from collections import Counter, deque
from typing import Any, Callable, Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

try:
    import google.generativeai as genai
except ImportError:  # pragma: no cover - dependency is installed in deployment
    genai = None


APP_VERSION = "3.0.0"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GENERAL_WALLET = os.getenv(
    "GENERAL_PAYOUT_WALLET",
    "0xddd4099e38eddba33c04beaf034dd4241e6c7df3",
)
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "900"))
CACHE_MAX_ITEMS = int(os.getenv("CACHE_MAX_ITEMS", "5000"))
MAX_PROMPT_LENGTH = int(os.getenv("MAX_PROMPT_LENGTH", "12000"))
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")

if genai is not None and GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-flash")
else:
    model = None

app = FastAPI(
    title="AuditGuard AI",
    version=APP_VERSION,
    description="PII redaction and prompt-injection defense API.",
)

# SQLite is intentionally small and local for the free Render tier.
conn = sqlite3.connect("database.db", check_same_thread=False)
conn.execute(
    """
    CREATE TABLE IF NOT EXISTS api_keys (
        key TEXT PRIMARY KEY,
        owner_wallet TEXT NOT NULL,
        tier TEXT NOT NULL,
        requests_left INTEGER NOT NULL
    )
    """
)
conn.commit()
db_lock = threading.Lock()

PII_PATTERNS = {
    "EMAIL": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "PHONE": re.compile(r"\+?[0-9]{9,15}"),
    "CARD": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
    "API_KEY": re.compile(r"(?:sk-|AIza|ghp_)[a-zA-Z0-9_-]{20,}"),
}
THREAT_PATTERNS = {
    "JAILBREAK": re.compile(
        r"\b(ignore|disregard|bypass|override)\b.{0,80}\b(previous|system|safety|instruction)",
        re.IGNORECASE,
    ),
    "SYSTEM_PROMPT_LEAK": re.compile(
        r"\b(reveal|show|print|leak|dump)\b.{0,80}\b(system prompt|hidden instruction|developer message)",
        re.IGNORECASE,
    ),
    "ROLE_ESCALATION": re.compile(
        r"\b(pretend|act as|you are now)\b.{0,60}\b(admin|developer|unfiltered|evil)",
        re.IGNORECASE,
    ),
}

# Bounded TTL cache: avoids repeated Gemini calls without unbounded memory growth.
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()
_recent_latencies = deque(maxlen=200)
_metrics = Counter()
_metrics_lock = threading.Lock()


class ScanRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_LENGTH)


class AgentStatus(BaseModel):
    name: str
    role: str
    status: str
    capability: str


def record_metric(name: str, value: int = 1) -> None:
    with _metrics_lock:
        _metrics[name] += value


def mask_text(text: str) -> str:
    for label, pattern in PII_PATTERNS.items():
        text = pattern.sub(f"[REDACTED_{label}]", text)
    return text


def cache_key(prompt: str) -> str:
    return hashlib.sha256(prompt.strip().lower().encode("utf-8")).hexdigest()


def cache_get(key: str) -> Optional[dict[str, Any]]:
    now = time.monotonic()
    with _cache_lock:
        item = _cache.get(key)
        if not item:
            return None
        created, value = item
        if now - created > CACHE_TTL_SECONDS:
            _cache.pop(key, None)
            return None
        return dict(value)


def cache_put(key: str, value: dict[str, Any]) -> None:
    with _cache_lock:
        if len(_cache) >= CACHE_MAX_ITEMS:
            oldest_key = min(_cache, key=lambda candidate: _cache[candidate][0])
            _cache.pop(oldest_key, None)
        _cache[key] = (time.monotonic(), dict(value))


def heuristic_threats(text: str) -> list[str]:
    return [name for name, pattern in THREAT_PATTERNS.items() if pattern.search(text)]


def gemini_threat_check(clean_prompt: str) -> tuple[bool, str]:
    if model is None:
        reasons = heuristic_threats(clean_prompt)
        return bool(reasons), "heuristic" if reasons else "heuristic_clear"

    eval_prompt = (
        "Classify this prompt for jailbreak or system-prompt-leak attempts. "
        "Return ONLY JSON in this exact shape: "
        '{"is_threat": true, "reason": "short_reason"}. '
        f"\nPrompt: {clean_prompt}"
    )
    try:
        result = model.generate_content(eval_prompt)
        raw = result.text.upper()
        is_threat = "TRUE" in raw and "IS_THREAT" in raw
        return is_threat, "gemini"
    except Exception:
        reasons = heuristic_threats(clean_prompt)
        record_metric("gemini_fallbacks")
        return bool(reasons), "heuristic_fallback" if reasons else "heuristic_clear"


def require_agent_key(authorization: Optional[str]) -> None:
    if not AGENT_API_KEY:
        return
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if supplied != AGENT_API_KEY:
        raise HTTPException(status_code=401, detail="Valid API key required")


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "version": APP_VERSION,
        "gemini_configured": bool(model),
        "cache_entries": len(_cache),
    }


@app.get("/metrics")
def metrics(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    require_agent_key(authorization)
    with _metrics_lock:
        data = dict(_metrics)
    with _cache_lock:
        data["cache_entries"] = len(_cache)
    data["cache_ttl_seconds"] = CACHE_TTL_SECONDS
    data["recent_latency_ms"] = round(sum(_recent_latencies) / len(_recent_latencies), 2) if _recent_latencies else 0
    return data


@app.get("/v1/agents/status", response_model=list[AgentStatus])
def agent_status(authorization: Optional[str] = Header(default=None)) -> list[AgentStatus]:
    require_agent_key(authorization)
    return [
        AgentStatus(name="CTO", role="Reliability", status="active", capability="bounded cache, health and metrics"),
        AgentStatus(name="CFO", role="Payments", status="guarded", capability="order metadata; transaction verification remains required before activation"),
        AgentStatus(name="CEO", role="Orchestration", status="active", capability="service-level status and operational reporting"),
        AgentStatus(name="CMO", role="Growth", status="informational", capability="landing page and public API documentation"),
        AgentStatus(name="PR/DevRel", role="Integrations", status="informational", capability="OpenAPI documentation and API examples"),
    ]


@app.post("/v1/scan")
async def scan_prompt(
    req: ScanRequest, authorization: Optional[str] = Header(default=None)
) -> dict[str, Any]:
    require_agent_key(authorization)
    started = time.perf_counter()
    clean = mask_text(req.prompt)
    key = cache_key(clean)
    cached = cache_get(key)
    if cached is not None:
        record_metric("scans_total")
        record_metric("cache_hits")
        cached["cache_hit"] = True
        cached["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return cached

    threat_reasons = heuristic_threats(clean)
    is_threat, engine = gemini_threat_check(clean)
    if threat_reasons and engine.startswith("gemini"):
        is_threat = True
    result = {
        "status": "success",
        "clean_prompt": clean,
        "is_threat": is_threat,
        "action": "BLOCK" if is_threat else "ALLOW",
        "detection_engine": engine,
        "threat_signals": threat_reasons,
        "cache_hit": False,
    }
    cache_put(key, result)
    latency = round((time.perf_counter() - started) * 1000, 2)
    result["latency_ms"] = latency
    _recent_latencies.append(latency)
    record_metric("scans_total")
    record_metric("threats_blocked" if is_threat else "prompts_allowed")
    return result


@app.post("/v1/order-pro")
async def create_order(buyer_wallet: str) -> dict[str, Any]:
    return {
        "price_usdt": 19.0,
        "network": "BEP-20 (BNB Smart Chain)",
        "pay_to_address": GENERAL_WALLET,
        "buyer_wallet": buyer_wallet,
        "instructions": "O'tkazma bajargach, tx_hash bilan /v1/activate-key endpointiga murojaat qiling.",
        "verification": "Activation must be backed by transaction verification before production billing.",
    }


@app.post("/v1/activate-key")
async def activate_key(tx_hash: str, buyer_wallet: str) -> dict[str, Any]:
    # Do not issue paid access solely because an arbitrary tx_hash was submitted.
    raise HTTPException(
        status_code=501,
        detail="On-chain transaction verification is not enabled yet; no key was issued.",
    )


@app.get("/", response_class=HTMLResponse)
async def landing_page() -> str:
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
      <title>AuditGuard AI — Prompt Security &amp; PII Redaction AaaS</title>
      <style>
        body {{ font-family: -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; max-width: 800px; margin: auto; }}
        .card {{ background: #1e293b; padding: 24px; border-radius: 12px; margin-bottom: 24px; border: 1px solid #334155; }}
        textarea, button {{ width: 100%; padding: 12px; margin-top: 8px; border-radius: 6px; box-sizing: border-box; }}
        textarea {{ background: #0f172a; color: #fff; border: 1px solid #475569; }}
        button {{ background: #38bdf8; color: #0f172a; font-weight: bold; cursor: pointer; border: none; }}
        .badge {{ background: #22c55e; color: #000; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
      </style>
    </head>
    <body>
      <h1>AuditGuard AI <span class="badge">v{APP_VERSION} Live</span></h1>
      <p>PII redaction, prompt-injection defense, bounded caching and operational metrics.</p>
      <div class="card"><h3>Try Live Demo</h3>
        <textarea id="promptInput" rows="3" maxlength="{MAX_PROMPT_LENGTH}" placeholder="Enter a prompt..."></textarea>
        <button onclick="testScan()">Test API Scan</button><pre id="output"></pre>
      </div>
      <p><a href="/docs" style="color:#38bdf8">OpenAPI / Swagger documentation</a></p>
      <script>
        async function testScan() {{
          const text = document.getElementById('promptInput').value;
          const res = await fetch('/v1/scan', {{ method: 'POST', headers: {{ 'Content-Type': 'application/json' }}, body: JSON.stringify({{ prompt: text }}) }});
          document.getElementById('output').innerText = JSON.stringify(await res.json(), null, 2);
        }}
      </script>
    </body></html>
    """
```
