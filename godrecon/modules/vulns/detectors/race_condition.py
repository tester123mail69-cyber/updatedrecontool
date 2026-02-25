"""P3 — Race Condition detector."""

from __future__ import annotations

import asyncio
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_RACE_CONCURRENT = 10  # Number of simultaneous requests
_SENSITIVE_KEYWORDS = [
    "password",
    "reset",
    "payment",
    "checkout",
    "transfer",
    "coupon",
    "redeem",
    "vote",
    "register",
]


class RaceConditionDetector:
    """Detects Race Condition vulnerabilities by sending concurrent requests."""

    def __init__(
        self,
        http_client: Any,
        safe_mode: bool = True,
        max_payloads: int = 10,
    ) -> None:
        self.http = http_client
        self.safe_mode = safe_mode
        self.max_payloads = max_payloads

    async def scan(self, url: str, params: List[str]) -> List[Finding]:
        """Send concurrent requests to detect race conditions on sensitive endpoints."""
        findings: List[Finding] = []

        url_lower = url.lower()
        if not any(kw in url_lower for kw in _SENSITIVE_KEYWORDS):
            return findings

        async def _single_request() -> dict:
            try:
                resp = await self.http.get(url)
                return resp or {}
            except Exception as exc:
                logger.debug("Race condition request error: %s", exc)
                return {}

        try:
            tasks = [_single_request() for _ in range(_RACE_CONCURRENT)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            success_responses = [
                r for r in responses
                if isinstance(r, dict) and r.get("status_code") in (200, 201)
            ]

            if len(success_responses) > 1:
                # Multiple concurrent successes on a sensitive endpoint
                findings.append(Finding(
                    title=f"Potential Race Condition — {url}",
                    description=(
                        f"Sensitive endpoint '{url}' returned {len(success_responses)} "
                        f"successful responses to {_RACE_CONCURRENT} concurrent requests. "
                        "Manual verification required to confirm exploitation."
                    ),
                    severity="medium",
                    confidence=0.5,
                    data={
                        "url": url,
                        "concurrent_requests": _RACE_CONCURRENT,
                        "success_count": len(success_responses),
                    },
                    tags=["race-condition", "p3", "medium"],
                    evidence=(
                        f"{len(success_responses)}/{_RACE_CONCURRENT} concurrent requests "
                        "to sensitive endpoint returned success"
                    ),
                ))
        except Exception as exc:
            logger.debug("Race condition scan error: %s", exc)

        return findings
