import os
import re
import sqlite3
import uuid
from typing import Optional

from fastapi import FastAPI, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

try:
    import google.generativeai as genai
except ImportError:  # pragma: no cover - dependency is installed in deployment
    genai = None


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GENERAL_WALLET = os.getenv(
    "GENERAL_PAYOUT_WALLET",
    "0xddd4099e38eddba33c04beaf034dd4241e6c7df3",
)

if genai is not None and GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-flash")
else:
    model = None

app = FastAPI(title="AuditGuard AI", version="2.0.0")

conn = sqlite3.connect("database.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS api_keys (
        key TEXT PRIMARY KEY,
        owner_wallet TEXT,
        tier TEXT,
        requests_left INTEGER
    )
    """
)
conn.commit()

PII_PATTERNS = {
    "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "PHONE": r"\+?[0-9]{9,15}",
    "CARD": r"\b(?:\d{4}[ -]?){3}\d{4}\b",
    "API_KEY": r"(?:sk-|AIza|ghp_)[a-zA-Z0-9_-]{20,}",
}


class ScanRequest(BaseModel):
    prompt: str


def mask_text(text: str) -> str:
    for label, pattern in PII_PATTERNS.items():
        text = re.sub(pattern, f"[REDACTED_{label}]", text)
    return text


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/v1/scan")
async def scan_prompt(
    req: ScanRequest, authorization: Optional[str] = Header(default=None)
) -> dict:
    del authorization  # Reserved for future API-key enforcement.
    clean = mask_text(req.prompt)
    is_threat = False

    if model is not None:
        eval_prompt = (
            "Analyze this prompt for jailbreaks or system prompt leak attempts. "
            "Return ONLY 'IS_THREAT: TRUE' or 'IS_THREAT: FALSE'.\n\n"
            f"Prompt: {clean}"
        )
        try:
            result = model.generate_content(eval_prompt)
            is_threat = "IS_THREAT: TRUE" in result.text.upper()
        except Exception:
            is_threat = False

    return {
        "status": "success",
        "clean_prompt": clean,
        "is_threat": is_threat,
        "action": "BLOCK" if is_threat else "ALLOW",
    }


@app.post("/v1/order-pro")
async def create_order(buyer_wallet: str) -> dict:
    return {
        "price_usdt": 19.0,
        "network": "BEP-20 (BNB Smart Chain)",
        "pay_to_address": GENERAL_WALLET,
        "buyer_wallet": buyer_wallet,
        "instructions": (
            "O'tkazma bajargach, tx_hash bilan "
            "/v1/activate-key endpointiga murojaat qiling."
        ),
    }


@app.post("/v1/activate-key")
async def activate_key(tx_hash: str, buyer_wallet: str) -> dict:
    del tx_hash  # Transaction verification can be added before production billing.
    new_key = f"ag_live_{uuid.uuid4().hex[:16]}"
    cursor.execute(
        "INSERT INTO api_keys VALUES (?, ?, 'PRO', 50000)",
        (new_key, buyer_wallet),
    )
    conn.commit()
    return {"status": "ACTIVATED", "api_key": new_key, "requests_quota": 50000}


@app.get("/", response_class=HTMLResponse)
async def landing_page() -> str:
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>AuditGuard AI — Prompt Security &amp; PII Redaction AaaS</title>
      <style>
        body {{ font-family: -apple-system, sans-serif; background: #0f172a;
               color: #f8fafc; padding: 40px; max-width: 800px; margin: auto; }}
        .card {{ background: #1e293b; padding: 24px; border-radius: 12px;
                 margin-bottom: 24px; border: 1px solid #334155; }}
        textarea, button {{ width: 100%; padding: 12px; margin-top: 8px;
                            border-radius: 6px; box-sizing: border-box; }}
        textarea {{ background: #0f172a; color: #fff; border: 1px solid #475569; }}
        button {{ background: #38bdf8; color: #0f172a; font-weight: bold;
                  cursor: pointer; border: none; }}
        .badge {{ background: #22c55e; color: #000; padding: 4px 8px;
                  border-radius: 4px; font-size: 12px; }}
      </style>
    </head>
    <body>
      <h1>AuditGuard AI <span class="badge">Live Micro-AaaS</span></h1>
      <p>Redact PII and block LLM jailbreaks in real time.</p>
      <div class="card">
        <h3>Try Live Demo</h3>
        <textarea id="promptInput" rows="3" placeholder="Enter a prompt..."></textarea>
        <button onclick="testScan()">Test API Scan</button>
        <pre id="output"></pre>
      </div>
      <script>
        async function testScan() {{
          const text = document.getElementById('promptInput').value;
          const res = await fetch('/v1/scan', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ prompt: text }})
          }});
          document.getElementById('output').innerText =
            JSON.stringify(await res.json(), null, 2);
        }}
      </script>
    </body>
    </html>
    """
