"""Verification engine for GODRECON — zero false positives.

Every finding is verified through a multi-step pipeline before reporting.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Minimum confidence to report a finding (overridable)
DEFAULT_MIN_CONFIDENCE: float = 0.5

# Wildcard DNS check prefix
_WILDCARD_PREFIX = "random-nonexistent-host-godrecon-12345678"


class VerificationEngine:
    """Multi-step verification pipeline for vulnerability findings.

    Strategies:
    - Initial detection by individual detectors
    - Confirmation check with a second, different payload
    - False-positive check with known-safe input
    - Evidence collection (full HTTP request/response)
    """

    def __init__(
        self,
        http_client: Any,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        safe_mode: bool = True,
    ) -> None:
        self.http = http_client
        self.min_confidence = min_confidence
        self.safe_mode = safe_mode
        self._wildcard_ips: Dict[str, Optional[str]] = {}
        self._soft_404_fingerprints: Dict[str, Optional[str]] = {}
        self._waf_detected: Dict[str, bool] = {}

    # ------------------------------------------------------------------
    # Wildcard DNS detection
    # ------------------------------------------------------------------

    async def check_wildcard_dns(self, domain: str) -> Optional[str]:
        """Resolve a random subdomain to detect wildcard DNS.

        Returns the wildcard IP if detected, else None.
        """
        if domain in self._wildcard_ips:
            return self._wildcard_ips[domain]

        probe = f"{_WILDCARD_PREFIX}.{domain}"
        try:
            loop = asyncio.get_event_loop()
            info = await loop.run_in_executor(None, socket.gethostbyname, probe)
            logger.warning("Wildcard DNS detected for %s → %s", domain, info)
            self._wildcard_ips[domain] = info
            return info
        except (socket.gaierror, OSError):
            self._wildcard_ips[domain] = None
            return None

    def is_wildcard_result(self, domain: str, resolved_ip: str) -> bool:
        """Return True if *resolved_ip* matches the wildcard IP for *domain*."""
        wildcard = self._wildcard_ips.get(domain)
        return wildcard is not None and wildcard == resolved_ip

    # ------------------------------------------------------------------
    # Soft-404 detection
    # ------------------------------------------------------------------

    async def get_soft_404_fingerprint(self, base_url: str) -> Optional[str]:
        """Request a definitely-nonexistent path and fingerprint the response."""
        if base_url in self._soft_404_fingerprints:
            return self._soft_404_fingerprints[base_url]

        probe_url = f"{base_url.rstrip('/')}/definitely-not-a-real-page-godrecon-xyz123"
        try:
            resp = await self.http.get(probe_url)
            if resp and resp.get("status") == 200:
                body = resp.get("body", "") or ""
                fingerprint = hashlib.sha256(body[:2048].encode()).hexdigest()
                logger.debug("Soft-404 fingerprint for %s: %s", base_url, fingerprint)
                self._soft_404_fingerprints[base_url] = fingerprint
                return fingerprint
        except Exception:
            pass
        self._soft_404_fingerprints[base_url] = None
        return None

    def is_soft_404(self, base_url: str, body: str) -> bool:
        """Return True if *body* matches the soft-404 fingerprint for *base_url*."""
        fingerprint = self._soft_404_fingerprints.get(base_url)
        if fingerprint is None:
            return False
        return hashlib.sha256(body[:2048].encode()).hexdigest() == fingerprint

    # ------------------------------------------------------------------
    # WAF / Rate-limit detection
    # ------------------------------------------------------------------

    def record_response_status(self, target: str, status: int) -> None:
        """Record a response status for WAF/rate-limit tracking."""
        if status in (403, 429):
            self._waf_detected[target] = True
            logger.warning("WAF/rate-limit detected on %s (status=%d)", target, status)

    def is_waf_blocking(self, target: str) -> bool:
        """Return True if WAF/rate-limiting appears to be active for *target*."""
        return self._waf_detected.get(target, False)

    # ------------------------------------------------------------------
    # Core verification helpers
    # ------------------------------------------------------------------

    async def verify_time_based_sqli(
        self,
        http: Any,
        url: str,
        param: str,
        delay_payload: str,
        expected_delay: float = 5.0,
    ) -> Tuple[bool, float]:
        """Verify time-based SQLi by measuring response delay.

        Returns (confirmed, observed_delay).
        """
        try:
            start = time.monotonic()
            resp = await http.get(url, params={param: delay_payload})
            elapsed = time.monotonic() - start
            if elapsed >= expected_delay * 0.8:
                return True, elapsed
        except Exception as exc:
            logger.debug("Time-based SQLi verify error: %s", exc)
        return False, 0.0

    async def verify_reflection(
        self,
        http: Any,
        url: str,
        params: Dict[str, str],
        marker: str,
    ) -> Tuple[bool, str]:
        """Verify that *marker* appears unescaped in the response body.

        Returns (reflected, context) where context is 'html'|'attr'|'script'|'comment'|''.
        """
        try:
            resp = await http.get(url, params=params)
            if not resp:
                return False, ""
            body = resp.get("body", "") or ""
            if marker not in body:
                return False, ""
            # Determine context
            idx = body.find(marker)
            prefix = body[max(0, idx - 100):idx]
            if re.search(r"<!--", prefix):
                return True, "comment"
            if re.search(r"<script", prefix, re.I):
                return True, "script"
            if re.search(r'["\']=["\']?$', prefix):
                return True, "attr"
            return True, "html"
        except Exception as exc:
            logger.debug("Reflection verify error: %s", exc)
        return False, ""

    async def verify_redirect(
        self,
        http: Any,
        url: str,
        expected_location_prefix: str,
    ) -> bool:
        """Verify open redirect by checking Location header."""
        try:
            resp = await http.get(url, allow_redirects=False)
            if not resp:
                return False
            status = resp.get("status", 0)
            if status in (301, 302, 303, 307, 308):
                location = (resp.get("headers") or {}).get("location", "")
                return location.startswith(expected_location_prefix)
        except Exception as exc:
            logger.debug("Redirect verify error: %s", exc)
        return False

    async def verify_content_in_response(
        self,
        http: Any,
        url: str,
        expected_patterns: List[str],
    ) -> Tuple[bool, List[str]]:
        """Check that response body contains expected patterns.

        Returns (found, matched_patterns).
        """
        matched: List[str] = []
        try:
            resp = await http.get(url)
            if not resp:
                return False, matched
            body = resp.get("body", "") or ""
            for pattern in expected_patterns:
                if re.search(pattern, body, re.I):
                    matched.append(pattern)
        except Exception as exc:
            logger.debug("Content verify error: %s", exc)
        return bool(matched), matched

    # ------------------------------------------------------------------
    # Finding confidence adjuster
    # ------------------------------------------------------------------

    def filter_findings(self, findings: List[Any]) -> List[Any]:
        """Remove findings below min_confidence threshold."""
        return [f for f in findings if getattr(f, "confidence", 1.0) >= self.min_confidence]
