"""P2 — HTTP Request Smuggling detector."""

from __future__ import annotations

from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Conflicting CL/TE headers that can trigger smuggling
_SMUGGLING_PROBES = [
    {
        "headers": {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nX",
        "type": "CL.TE",
    },
    {
        "headers": {
            "Transfer-Encoding": "chunked",
            "Content-Length": "4",
        },
        "body": "1\r\nZ\r\n0\r\n\r\n",
        "type": "TE.CL",
    },
    {
        "headers": {
            "Transfer-Encoding": "chunked",
            "Transfer-Encoding": " chunked",  # duplicate TE
        },
        "body": "0\r\n\r\n",
        "type": "TE.TE (obfuscated)",
    },
]

_SMUGGLING_ERROR_INDICATORS = [
    "400 Bad Request",
    "Invalid request",
    "Chunked encoding error",
    "Malformed request",
    "stream error",
]


class HTTPSmugglingDetector:
    """Detects HTTP Request Smuggling vulnerabilities."""

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
        """Probe for HTTP Request Smuggling using conflicting headers."""
        findings: List[Finding] = []

        for probe in _SMUGGLING_PROBES[: self.max_payloads]:
            try:
                resp = await self.http.post(
                    url,
                    data=probe["body"],
                    headers=probe["headers"],
                )
                if not resp:
                    continue

                status = resp.get("status_code", 0)
                body = (resp.get("body", "") or "").lower()

                # Unexpected 200 with conflicting headers is suspicious
                if status == 200:
                    findings.append(Finding(
                        title=f"Potential HTTP Request Smuggling ({probe['type']}) — {url}",
                        description=(
                            f"Endpoint accepted conflicting CL/TE headers ({probe['type']}) "
                            "without rejection. Manual verification recommended."
                        ),
                        severity="high",
                        confidence=0.5,
                        data={
                            "url": url,
                            "probe_type": probe["type"],
                            "headers": probe["headers"],
                            "method": "POST",
                        },
                        tags=["http-smuggling", "p2", "high"],
                        evidence=f"Server returned HTTP 200 for {probe['type']} probe",
                    ))

                # Specific error messages indicate the server is processing CL/TE
                for indicator in _SMUGGLING_ERROR_INDICATORS:
                    if indicator.lower() in body:
                        findings.append(Finding(
                            title=f"HTTP Request Smuggling Indicator ({probe['type']}) — {url}",
                            description=(
                                f"Server returned an error suggesting it processes CL/TE headers "
                                f"({probe['type']}). This may indicate susceptibility to smuggling."
                            ),
                            severity="high",
                            confidence=0.55,
                            data={
                                "url": url,
                                "probe_type": probe["type"],
                                "headers": probe["headers"],
                                "method": "POST",
                            },
                            tags=["http-smuggling", "p2", "high"],
                            evidence=f"Error indicator '{indicator}' found in response",
                        ))
                        break
            except Exception as exc:
                logger.debug("HTTP smuggling scan error: %s", exc)

        return findings
