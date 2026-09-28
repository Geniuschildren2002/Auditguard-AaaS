from __future__ import annotations

from typing import Any, Tuple

import requests


class AuditGuard:
    """Small client for the AuditGuard scan API."""

    def __init__(self, api_url: str = "https://auditguard-aaas.onrender.com", api_key: str | None = None, timeout: float = 15.0):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def scan(self, prompt: str) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        response = requests.post(
            f"{self.api_url}/v1/scan",
            json={"prompt": prompt},
            headers=headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def protect(self, prompt: str) -> Tuple[str, bool]:
        result = self.scan(prompt)
        return result["clean_prompt"], not result["is_threat"]
