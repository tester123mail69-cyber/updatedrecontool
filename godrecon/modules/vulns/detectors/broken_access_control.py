"""P2 — Broken Access Control detector."""

from __future__ import annotations

from typing import Any, List
from urllib.parse import urlparse, urljoin

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/api/admin",
    "/dashboard",
    "/admin/dashboard",
    "/manage",
    "/management",
    "/administrator",
    "/wp-admin",
    "/cpanel",
]


class BrokenAccessControlDetector:
    """Detects Broken Access Control vulnerabilities."""

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
        """Try accessing privileged paths without authentication."""
        findings: List[Finding] = []

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in _ADMIN_PATHS[: self.max_payloads]:
            target_url = urljoin(base, path)
            try:
                resp = await self.http.get(target_url)
                if not resp:
                    continue
                status = resp.get("status_code", 0)
                body = (resp.get("body", "") or "").lower()

                # 200 response to admin path without auth is suspicious
                if status == 200 and any(
                    kw in body for kw in ["admin", "dashboard", "panel", "management", "control"]
                ):
                    findings.append(Finding(
                        title=f"Broken Access Control — {target_url}",
                        description=(
                            f"Admin/privileged path '{path}' returned HTTP 200 without authentication. "
                            "This may indicate broken access control."
                        ),
                        severity="high",
                        confidence=0.75,
                        data={
                            "url": target_url,
                            "path": path,
                            "status": status,
                            "method": "GET",
                        },
                        tags=["broken-access-control", "p2", "high"],
                        evidence=f"HTTP 200 returned for admin path '{path}' with admin-related content",
                    ))
                elif status == 200:
                    findings.append(Finding(
                        title=f"Admin Path Accessible — {target_url}",
                        description=(
                            f"Path '{path}' returned HTTP 200 without authentication. "
                            "Manual review recommended."
                        ),
                        severity="high",
                        confidence=0.5,
                        data={
                            "url": target_url,
                            "path": path,
                            "status": status,
                            "method": "GET",
                        },
                        tags=["broken-access-control", "p2", "high"],
                        evidence=f"HTTP 200 returned for potentially privileged path '{path}'",
                    ))
            except Exception as exc:
                logger.debug("Broken access control scan error for %s: %s", target_url, exc)

        return findings
