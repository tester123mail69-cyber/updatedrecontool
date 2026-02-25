"""P1 — OS Command Injection detector."""

from __future__ import annotations

from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_CMD_MARKER = "GODRECON_CMD"

_CMD_PAYLOADS = [
    f"; echo {_CMD_MARKER}",
    f"| echo {_CMD_MARKER}",
    f"&& echo {_CMD_MARKER}",
    f"`echo {_CMD_MARKER}`",
    f"$(echo {_CMD_MARKER})",
]


class CommandInjectionDetector:
    """Detects OS Command Injection vulnerabilities in URL parameters."""

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
        """Scan URL parameters for command injection."""
        findings: List[Finding] = []

        for param in params:
            for payload in _CMD_PAYLOADS[: self.max_payloads]:
                try:
                    resp = await self.http.get(url, params={param: payload})
                    if not resp:
                        continue
                    body = resp.get("body", "") or ""
                    if _CMD_MARKER in body:
                        findings.append(Finding(
                            title=f"OS Command Injection — {url}",
                            description=(
                                f"Parameter '{param}' is vulnerable to command injection. "
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
                            tags=["command-injection", "p1", "critical"],
                            evidence=f"Marker '{_CMD_MARKER}' echoed back in response",
                        ))
                        break
                except Exception as exc:
                    logger.debug("Command injection scan error: %s", exc)

        return findings
