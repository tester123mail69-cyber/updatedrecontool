"""P2 — WebSocket Hijacking detector."""

from __future__ import annotations

import re
from typing import Any, List
from urllib.parse import urlparse

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_WS_PATTERNS = [
    r"ws://",
    r"wss://",
    r'new WebSocket\(',
    r"Upgrade:\s*websocket",
    r"websocket",
]


class WebSocketHijackingDetector:
    """Detects WebSocket endpoints and checks for missing Origin validation."""

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
        """Scan for WebSocket endpoints and missing Origin header checks."""
        findings: List[Finding] = []

        try:
            resp = await self.http.get(url)
            if not resp:
                return findings

            body = resp.get("body", "") or ""
            resp_headers = resp.get("headers", {}) or {}
            status = resp.get("status_code", 0)

            # Detect WebSocket references in the response
            ws_found = any(re.search(p, body, re.I) for p in _WS_PATTERNS)
            upgrade_header = resp_headers.get("Upgrade", "") or resp_headers.get("upgrade", "") or ""
            ws_upgrade = "websocket" in upgrade_header.lower()

            if not ws_found and not ws_upgrade:
                return findings

            # Check if the WebSocket upgrade accepts arbitrary Origins
            parsed = urlparse(url)
            malicious_origin = "https://evil.com"
            ws_headers = {
                "Origin": malicious_origin,
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            }

            try:
                ws_resp = await self.http.get(url, headers=ws_headers)
                if ws_resp:
                    ws_status = ws_resp.get("status_code", 0)
                    ws_resp_headers = ws_resp.get("headers", {}) or {}
                    origin_allowed = ws_resp_headers.get("Access-Control-Allow-Origin", "") or ""

                    # 101 Switching Protocols with evil origin = no origin check
                    if ws_status == 101 or "evil.com" in origin_allowed:
                        findings.append(Finding(
                            title=f"WebSocket Cross-Site Hijacking — {url}",
                            description=(
                                "WebSocket endpoint accepted connection from a cross-origin request "
                                "without Origin validation. This may allow WebSocket hijacking."
                            ),
                            severity="high",
                            confidence=0.85,
                            data={
                                "url": url,
                                "injected_origin": malicious_origin,
                                "ws_status": ws_status,
                            },
                            tags=["websocket-hijacking", "p2", "high"],
                            evidence=f"WebSocket upgrade accepted with Origin: {malicious_origin}",
                        ))
                    else:
                        # WS endpoint found but origin check seems present
                        findings.append(Finding(
                            title=f"WebSocket Endpoint Detected — {url}",
                            description=(
                                "A WebSocket endpoint was detected. "
                                "Verify that Origin validation is enforced server-side."
                            ),
                            severity="high",
                            confidence=0.5,
                            data={"url": url},
                            tags=["websocket-hijacking", "p2", "high"],
                            evidence="WebSocket references found in response",
                        ))
            except Exception as exc:
                logger.debug("WebSocket origin probe error: %s", exc)
                # Still report the WS endpoint was found
                findings.append(Finding(
                    title=f"WebSocket Endpoint Detected — {url}",
                    description=(
                        "A WebSocket endpoint was detected. "
                        "Verify that Origin validation is enforced server-side."
                    ),
                    severity="high",
                    confidence=0.5,
                    data={"url": url},
                    tags=["websocket-hijacking", "p2", "high"],
                    evidence="WebSocket references found in response body",
                ))
        except Exception as exc:
            logger.debug("WebSocket hijacking scan error: %s", exc)

        return findings
