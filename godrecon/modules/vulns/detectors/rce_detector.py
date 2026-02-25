"""P1 — Remote Code Execution (RCE) detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_RCE_PAYLOADS = [
    "; id",
    "| id",
    "&& id",
    "`id`",
    "$(id)",
]

_RCE_OUTPUT_PATTERNS = [
    r"uid=\d+",
    r"root:",
    r"www-data",
]


class RCEDetector:
    """Detects Remote Code Execution vulnerabilities in URL parameters."""

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
        """Scan URL parameters for RCE."""
        findings: List[Finding] = []

        for param in params:
            for payload in _RCE_PAYLOADS[: self.max_payloads]:
                try:
                    resp = await self.http.get(url, params={param: payload})
                    if not resp:
                        continue
                    body = resp.get("body", "") or ""
                    for pattern in _RCE_OUTPUT_PATTERNS:
                        if re.search(pattern, body, re.I):
                            findings.append(Finding(
                                title=f"Remote Code Execution — {url}",
                                description=(
                                    f"Parameter '{param}' is vulnerable to RCE. "
                                    f"Payload: {payload}"
                                ),
                                severity="critical",
                                confidence=0.95,
                                data={
                                    "url": url,
                                    "param": param,
                                    "payload": payload,
                                    "method": "GET",
                                },
                                tags=["rce", "p1", "critical"],
                                evidence=f"OS command output pattern '{pattern}' matched in response",
                            ))
                            break
                except Exception as exc:
                    logger.debug("RCE scan error: %s", exc)

        return findings
