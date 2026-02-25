"""P1 — Insecure Deserialization detector."""

from __future__ import annotations

import re
from typing import Any, List

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Safe probe payloads (non-exploiting — trigger error messages only)
_DESER_PROBES = [
    # Truncated Java serialization magic bytes (base64)
    ("rO0ABXNy", "Java"),
    # Python pickle opcode probe
    ("gASVAAAAAAAAAA==", "Python"),
    # PHP unserialize probe
    ('O:4:"Test":0:{}', "PHP"),
]

_DESER_ERROR_PATTERNS = [
    r"java\.io\.ObjectInputStream",
    r"java\.io\.InvalidClassException",
    r"ClassNotFoundException",
    r"Serializable",
    r"pickle",
    r"_pickle",
    r"UnpicklingError",
    r"unserialize\(\)",
    r"O:[0-9]+:\"",
    r"deserialization",
    r"Deserialization",
]


class DeserializationDetector:
    """Detects Insecure Deserialization vulnerabilities."""

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
        """Probe for deserialization errors in URL parameters and POST body."""
        findings: List[Finding] = []

        for probe_value, lang in _DESER_PROBES[: self.max_payloads]:
            # Test via URL params
            for param in params:
                try:
                    resp = await self.http.get(url, params={param: probe_value})
                    if not resp:
                        continue
                    body = resp.get("body", "") or ""
                    for pattern in _DESER_ERROR_PATTERNS:
                        if re.search(pattern, body, re.I):
                            findings.append(Finding(
                                title=f"Insecure Deserialization ({lang}) — {url}",
                                description=(
                                    f"Parameter '{param}' may deserialize user input ({lang}). "
                                    f"Deserialization error pattern found in response."
                                ),
                                severity="critical",
                                confidence=0.75,
                                data={
                                    "url": url,
                                    "param": param,
                                    "probe": probe_value,
                                    "language": lang,
                                    "method": "GET",
                                },
                                tags=["deserialization", "p1", "critical"],
                                evidence=f"Deserialization error pattern '{pattern}' matched in response",
                            ))
                            break
                except Exception as exc:
                    logger.debug("Deserialization scan error: %s", exc)

            # Test via POST body
            try:
                resp = await self.http.post(url, data=probe_value)
                if not resp:
                    continue
                body = resp.get("body", "") or ""
                for pattern in _DESER_ERROR_PATTERNS:
                    if re.search(pattern, body, re.I):
                        findings.append(Finding(
                            title=f"Insecure Deserialization ({lang}) via POST — {url}",
                            description=(
                                f"POST body may be deserialized ({lang}). "
                                "Deserialization error pattern found in response."
                            ),
                            severity="critical",
                            confidence=0.75,
                            data={
                                "url": url,
                                "probe": probe_value,
                                "language": lang,
                                "method": "POST",
                            },
                            tags=["deserialization", "p1", "critical"],
                            evidence=f"Deserialization error pattern '{pattern}' matched in POST response",
                        ))
                        break
            except Exception as exc:
                logger.debug("Deserialization POST scan error: %s", exc)

        return findings
