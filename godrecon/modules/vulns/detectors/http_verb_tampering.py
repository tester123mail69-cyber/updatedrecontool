"""P4 — HTTP Verb Tampering detector."""

from __future__ import annotations

from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_ALTERNATIVE_METHODS = ["TRACE", "CONNECT", "PUT", "DELETE", "PATCH"]


class HTTPVerbTamperingDetector:
    """Detects HTTP Verb Tampering vulnerabilities."""

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
        """Test alternative HTTP methods on the target endpoint."""
        findings: List[Finding] = []

        for method in _ALTERNATIVE_METHODS[: self.max_payloads]:
            try:
                resp = await self.http.request(method, url)
                if not resp:
                    continue
                status = resp.get("status_code", 0)
                body = resp.get("body", "") or ""

                # TRACE: 200 with request echo is a vulnerability
                if method == "TRACE" and status == 200 and ("TRACE" in body or url in body):
                    findings.append(Finding(
                        title=f"HTTP TRACE Method Enabled — {url}",
                        description=(
                            "The TRACE method is enabled and echoes request content. "
                            "This can facilitate Cross-Site Tracing (XST) attacks."
                        ),
                        severity="low",
                        confidence=0.9,
                        data={"url": url, "method": method, "status": status},
                        tags=["verb-tampering", "p4", "low", "trace"],
                        evidence=f"TRACE returned HTTP 200 with request echo",
                    ))

                # PUT/DELETE returning 200/201/204 is unexpected and suspicious
                elif method in ("PUT", "DELETE", "PATCH") and status in (200, 201, 204):
                    findings.append(Finding(
                        title=f"HTTP {method} Method Allowed — {url}",
                        description=(
                            f"The {method} method returned HTTP {status} suggesting it is accepted. "
                            "Verify whether this is intentional and properly authorized."
                        ),
                        severity="low",
                        confidence=0.6,
                        data={"url": url, "method": method, "status": status},
                        tags=["verb-tampering", "p4", "low"],
                        evidence=f"HTTP {method} returned status {status}",
                    ))
            except Exception as exc:
                logger.debug("HTTP verb tampering scan error (%s): %s", method, exc)

        return findings
