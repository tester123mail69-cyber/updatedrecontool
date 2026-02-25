"""P2 — JWT attack detector."""

from __future__ import annotations

import base64
import json
import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)


def _decode_jwt_header(token: str) -> dict:
    """Decode JWT header without verification."""
    try:
        header_b64 = token.split(".")[0]
        # Add padding
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding
        header_bytes = base64.urlsafe_b64decode(header_b64)
        return json.loads(header_bytes)
    except Exception:
        return {}


class JWTDetector:
    """Detects JWT-related vulnerabilities in HTTP responses and headers."""

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
        """Scan URL response for JWT tokens and check for weaknesses."""
        findings: List[Finding] = []

        try:
            resp = await self.http.get(url)
            if not resp:
                return findings

            body = resp.get("body", "") or ""
            headers = resp.get("headers", {}) or {}

            # Collect text to search for JWTs
            search_text = body
            for header_val in headers.values():
                if isinstance(header_val, str):
                    search_text += " " + header_val

            tokens = _JWT_PATTERN.findall(search_text)
            for token in tokens:
                header = _decode_jwt_header(token)
                alg = header.get("alg", "")

                # Check for alg:none attack
                if alg.lower() == "none":
                    findings.append(Finding(
                        title=f"JWT Algorithm None Attack — {url}",
                        description=(
                            "A JWT token with 'alg: none' was detected. "
                            "This allows forging tokens without a valid signature."
                        ),
                        severity="high",
                        confidence=0.95,
                        data={"url": url, "token_prefix": token[:40], "alg": alg},
                        tags=["jwt", "p2", "high", "alg-none"],
                        evidence=f"JWT header alg='{alg}'",
                    ))

                # Flag presence for further manual review
                elif alg:
                    findings.append(Finding(
                        title=f"JWT Token Detected — {url}",
                        description=(
                            f"A JWT token using algorithm '{alg}' was found in the response. "
                            "Verify that strong secrets/keys are used and tokens are validated properly."
                        ),
                        severity="high",
                        confidence=0.7,
                        data={"url": url, "token_prefix": token[:40], "alg": alg},
                        tags=["jwt", "p2", "high"],
                        evidence=f"JWT token detected with alg='{alg}'",
                    ))
        except Exception as exc:
            logger.debug("JWT scan error: %s", exc)

        return findings
