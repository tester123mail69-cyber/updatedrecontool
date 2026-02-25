"""P2 — Prototype Pollution detector."""

from __future__ import annotations

from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_PP_PAYLOADS = [
    "__proto__[test]=GODRECON_PP",
    "constructor.prototype.test=GODRECON_PP",
    "__proto__.test=GODRECON_PP",
]

_PP_MARKER = "GODRECON_PP"


class PrototypePollutionDetector:
    """Detects Prototype Pollution vulnerabilities in URL parameters."""

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
        """Scan URL parameters for prototype pollution via reflection."""
        findings: List[Finding] = []

        for payload in _PP_PAYLOADS[: self.max_payloads]:
            try:
                resp = await self.http.get(url + ("&" if "?" in url else "?") + payload)
                if not resp:
                    continue
                body = resp.get("body", "") or ""
                if _PP_MARKER in body:
                    findings.append(Finding(
                        title=f"Prototype Pollution — {url}",
                        description=(
                            f"Prototype pollution payload was reflected in the response. "
                            f"Payload: {payload}"
                        ),
                        severity="high",
                        confidence=0.85,
                        data={
                            "url": url,
                            "payload": payload,
                            "method": "GET",
                        },
                        tags=["prototype-pollution", "p2", "high"],
                        evidence=f"Marker '{_PP_MARKER}' reflected in response after pollution payload",
                    ))
                    break
            except Exception as exc:
                logger.debug("Prototype pollution scan error: %s", exc)

        return findings
