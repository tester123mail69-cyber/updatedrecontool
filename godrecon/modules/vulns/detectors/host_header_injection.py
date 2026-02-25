"""P3 — Host Header Injection detector."""

from __future__ import annotations

from typing import Any, List
from urllib.parse import urlparse

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_MALICIOUS_HOSTS = [
    "evil.com",
    "evil.com:80",
    "attacker.com",
    "godrecon-test.evil.com",
]


class HostHeaderInjectionDetector:
    """Detects Host Header Injection vulnerabilities."""

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
        """Test for host header injection by injecting malicious Host values."""
        findings: List[Finding] = []

        for malicious_host in _MALICIOUS_HOSTS[: self.max_payloads]:
            try:
                headers = {"Host": malicious_host}
                resp = await self.http.get(url, headers=headers)
                if not resp:
                    continue

                body = resp.get("body", "") or ""
                resp_headers = resp.get("headers", {}) or {}
                status = resp.get("status_code", 0)

                # Check for reflection of injected host in body
                if malicious_host in body:
                    findings.append(Finding(
                        title=f"Host Header Injection (Reflection) — {url}",
                        description=(
                            f"Injected Host header '{malicious_host}' was reflected in the response body. "
                            "This can lead to password reset poisoning or cache poisoning attacks."
                        ),
                        severity="medium",
                        confidence=0.85,
                        data={
                            "url": url,
                            "injected_host": malicious_host,
                            "method": "GET",
                        },
                        tags=["host-header-injection", "p3", "medium"],
                        evidence=f"Injected host '{malicious_host}' found in response body",
                    ))
                    break

                # Check for redirect to injected host
                location = resp_headers.get("location", "") or resp_headers.get("Location", "") or ""
                if malicious_host in location:
                    findings.append(Finding(
                        title=f"Host Header Injection (Redirect) — {url}",
                        description=(
                            f"Injected Host header '{malicious_host}' caused a redirect to that host. "
                            "This can be exploited for open redirect or password reset poisoning."
                        ),
                        severity="medium",
                        confidence=0.9,
                        data={
                            "url": url,
                            "injected_host": malicious_host,
                            "redirect_location": location,
                            "method": "GET",
                        },
                        tags=["host-header-injection", "p3", "medium"],
                        evidence=f"Response Location header redirects to '{location}'",
                    ))
                    break
            except Exception as exc:
                logger.debug("Host header injection scan error: %s", exc)

        return findings
