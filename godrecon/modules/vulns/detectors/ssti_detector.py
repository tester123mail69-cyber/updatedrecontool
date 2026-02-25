"""P1 — Server-Side Template Injection (SSTI) detector."""

from __future__ import annotations

from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_SSTI_PAYLOADS = [
    ("{{7*7}}", ["49"]),
    ("${7*7}", ["49"]),
    ("<%= 7*7 %>", ["49"]),
    ("#{7*7}", ["49"]),
    ("*{7*7}", ["49"]),
    ("{{7*'7'}}", ["7777777", "49"]),
    ("${{7*7}}", ["49"]),
]


class SSTIDetector:
    """Detects Server-Side Template Injection vulnerabilities."""

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
        """Scan URL parameters for SSTI."""
        findings: List[Finding] = []

        for param in params:
            for payload, expected_outputs in _SSTI_PAYLOADS[: self.max_payloads]:
                try:
                    resp = await self.http.get(url, params={param: payload})
                    if not resp:
                        continue
                    body = resp.get("body", "") or ""
                    for expected in expected_outputs:
                        if expected in body:
                            findings.append(Finding(
                                title=f"Server-Side Template Injection — {url}",
                                description=(
                                    f"Parameter '{param}' is vulnerable to SSTI. "
                                    f"Payload '{payload}' evaluated to '{expected}'."
                                ),
                                severity="critical",
                                confidence=0.95,
                                data={
                                    "url": url,
                                    "param": param,
                                    "payload": payload,
                                    "expected": expected,
                                    "method": "GET",
                                },
                                tags=["ssti", "p1", "critical"],
                                evidence=f"Template expression evaluated: '{payload}' → '{expected}'",
                            ))
                            break
                except Exception as exc:
                    logger.debug("SSTI scan error: %s", exc)

        return findings
