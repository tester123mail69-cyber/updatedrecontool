"""Fuzzing Engine module for GODRECON.

Performs mutation-based and dictionary-based fuzzing on URL parameters,
detecting anomalies in status codes, response sizes, and error patterns.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlunparse

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Fuzz payloads grouped by strategy
_BOUNDARY_PAYLOADS = ["0", "-1", "999999", "2147483647", "-2147483648", "9999999999"]
_STRING_PAYLOADS = [
    "A" * 1000,
    "%00",
    "%00%00",
    "%s%s%s%s",
    "%n%n%n%n",
    "{{7*7}}",
    "${7*7}",
]
_SPECIAL_CHAR_PAYLOADS = ["<>\"'&;|", "';--", "\"><img src=x>", "../../../../etc/passwd"]
_ENCODING_PAYLOADS = [
    "%27%20OR%20%271%27%3D%271",  # URL-encoded SQLi
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",  # URL-encoded XSS
    "..%2F..%2F..%2Fetc%2Fpasswd",  # URL-encoded traversal
]

_ALL_PAYLOADS = (
    _BOUNDARY_PAYLOADS
    + _STRING_PAYLOADS
    + _SPECIAL_CHAR_PAYLOADS
    + _ENCODING_PAYLOADS
)

# Error patterns indicating interesting server behaviour
_ERROR_PATTERNS = [
    (re.compile(r"(?i)sql syntax|mysql_fetch|ORA-[0-9]+|sqlite.*error"), "SQL Error", "medium"),
    (re.compile(r"(?i)stack trace|traceback|exception in thread"), "Stack Trace Leak", "medium"),
    (re.compile(r"(?i)fatal error|undefined variable|warning:.*php"), "PHP Error", "low"),
    (re.compile(r"(?i)internal server error|application error"), "Server Error", "low"),
    (re.compile(r"(?i)/etc/passwd|root:x:0:0"), "Path Traversal", "high"),
    (re.compile(r"(?i)<script>alert\("), "XSS Reflection", "medium"),
]

# Significant response size deviation (bytes) to flag as anomaly
_SIZE_DEVIATION_THRESHOLD = 500
# Status codes that differ from baseline and are interesting
_INTERESTING_STATUS_CHANGES = {500, 502, 503, 403, 401, 200}


class FuzzingModule(BaseModule):
    """Smart fuzzing engine for URL parameters with anomaly detection."""

    name = "fuzzing"
    description = "Mutation and dictionary fuzzing for URL params with anomaly detection"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "fuzzing"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)

        general = config.general
        timeout = general.timeout
        proxy = general.proxy
        user_agents = general.user_agents
        max_tests = general.max_payload_tests

        base_url = f"https://{target}" if not target.startswith("http") else target

        # Collect URLs with parameters to fuzz
        fuzz_targets = await self._collect_fuzz_targets(target, base_url)
        if not fuzz_targets:
            logger.info("No parameterised URLs found for fuzzing on %s", target)
            result.raw = {"fuzz_targets": 0, "findings": 0}
            return result

        logger.info("Fuzzing %d URLs for %s", len(fuzz_targets), target)

        async with AsyncHTTPClient(
            timeout=timeout,
            user_agents=user_agents,
            proxy=proxy,
            verify_ssl=False,
            retries=0,
        ) as http:
            sem = asyncio.Semaphore(10)
            payloads = _ALL_PAYLOADS[:max_tests]

            async def _fuzz_url(url: str) -> List[Finding]:
                async with sem:
                    return await self._fuzz_target_url(http, url, payloads)

            fuzz_results = await asyncio.gather(
                *[_fuzz_url(u) for u in fuzz_targets],
                return_exceptions=True,
            )

        for fr in fuzz_results:
            if isinstance(fr, list):
                result.findings.extend(fr)

        result.raw = {
            "fuzz_targets": len(fuzz_targets),
            "payloads_per_target": len(payloads),
            "total_findings": len(result.findings),
        }
        logger.info(
            "Fuzzing complete — %d targets, %d findings", len(fuzz_targets), len(result.findings)
        )
        return result

    async def _collect_fuzz_targets(self, target: str, base_url: str) -> List[str]:
        """Get parameterised URLs from crawl store or return base URL."""
        try:
            from godrecon.modules.crawl import get_crawled_urls  # type: ignore
            urls = get_crawled_urls(target) or []
            param_urls = [u for u in urls if "?" in u]
            return param_urls[:50] if param_urls else [base_url + "?id=1"]
        except (ImportError, Exception):
            return [base_url + "?id=1"]

    async def _fuzz_target_url(
        self, http: AsyncHTTPClient, url: str, payloads: List[str]
    ) -> List[Finding]:
        """Fuzz all parameters in *url* with *payloads*, detect anomalies."""
        findings: List[Finding] = []

        # Get baseline response
        baseline = await self._safe_get(http, url)
        if not baseline:
            return findings
        baseline_status = baseline.get("status", 200)
        baseline_size = len(baseline.get("body", "") or "")

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return findings

        for param_name in params:
            for payload in payloads:
                fuzz_params = dict(params)
                fuzz_params[param_name] = [payload]
                fuzz_query = urlencode(
                    {k: v[0] for k, v in fuzz_params.items()}, quote_via=lambda s, *_: s
                )
                fuzz_url = urlunparse(parsed._replace(query=fuzz_query))
                resp = await self._safe_get(http, fuzz_url)
                if not resp:
                    continue

                status = resp.get("status", 200)
                body = resp.get("body", "") or ""
                size = len(body)

                # Check for error patterns
                for error_re, error_name, severity in _ERROR_PATTERNS:
                    if error_re.search(body):
                        findings.append(
                            Finding(
                                title=f"Fuzzing anomaly: {error_name} on {param_name}",
                                description=(
                                    f"Error pattern '{error_name}' detected in response.\n"
                                    f"URL: {fuzz_url}\nParam: {param_name}\nPayload: {payload[:100]}"
                                ),
                                severity=severity,
                                data={
                                    "url": fuzz_url,
                                    "param": param_name,
                                    "payload": payload[:100],
                                    "anomaly_type": error_name,
                                    "status": status,
                                },
                                tags=["fuzzing", "anomaly", error_name.lower().replace(" ", "-")],
                                evidence=error_name,
                                source_module=self.name,
                            )
                        )
                        break

                # Check for interesting status code change
                if status != baseline_status and status in _INTERESTING_STATUS_CHANGES:
                    findings.append(
                        Finding(
                            title=f"Fuzzing anomaly: Status change {baseline_status}→{status} on {param_name}",
                            description=(
                                f"Unexpected status code change detected.\n"
                                f"URL: {fuzz_url}\nParam: {param_name}\n"
                                f"Baseline: {baseline_status} → Fuzz: {status}\nPayload: {payload[:100]}"
                            ),
                            severity="info",
                            data={
                                "url": fuzz_url,
                                "param": param_name,
                                "payload": payload[:100],
                                "baseline_status": baseline_status,
                                "fuzz_status": status,
                                "anomaly_type": "status_change",
                            },
                            tags=["fuzzing", "anomaly", "status-change"],
                            source_module=self.name,
                        )
                    )

                # Check for significant response size deviation
                if abs(size - baseline_size) > _SIZE_DEVIATION_THRESHOLD:
                    findings.append(
                        Finding(
                            title=f"Fuzzing anomaly: Response size deviation on {param_name}",
                            description=(
                                f"Significant response size change detected.\n"
                                f"URL: {fuzz_url}\nParam: {param_name}\n"
                                f"Baseline size: {baseline_size} bytes → Fuzz: {size} bytes\n"
                                f"Payload: {payload[:100]}"
                            ),
                            severity="info",
                            data={
                                "url": fuzz_url,
                                "param": param_name,
                                "payload": payload[:100],
                                "baseline_size": baseline_size,
                                "fuzz_size": size,
                                "anomaly_type": "size_deviation",
                            },
                            tags=["fuzzing", "anomaly", "size-deviation"],
                            source_module=self.name,
                        )
                    )

        return findings

    @staticmethod
    async def _safe_get(
        http: AsyncHTTPClient, url: str
    ) -> Optional[Dict[str, Any]]:
        try:
            return await http.get(url, allow_redirects=False)
        except Exception:
            return None
