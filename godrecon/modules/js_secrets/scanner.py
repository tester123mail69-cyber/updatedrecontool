"""JS Secrets Scanner module for GODRECON.

Fetches JavaScript files from target URLs and scans them for secrets,
credentials, API keys, and other sensitive data using regex patterns
and Shannon entropy analysis.
"""

from __future__ import annotations

import asyncio
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Secret patterns: (name, regex, severity, description)
_SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
    (
        "AWS Access Key ID",
        r"AKIA[0-9A-Z]{16}",
        "critical",
        "Exposed AWS Access Key ID",
    ),
    (
        "AWS Secret Access Key",
        r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s]*[=:\"'\s]+([A-Za-z0-9/+=]{40})",
        "critical",
        "Exposed AWS Secret Access Key",
    ),
    (
        "Google API Key",
        r"AIza[0-9A-Za-z\-_]{35}",
        "high",
        "Exposed Google API Key",
    ),
    (
        "Firebase URL",
        r"https://[a-z0-9\-]+\.firebaseio\.com",
        "medium",
        "Firebase database URL found",
    ),
    (
        "Stripe Live Secret Key",
        r"sk_live_[0-9a-zA-Z]{24}",
        "critical",
        "Exposed Stripe live secret key",
    ),
    (
        "Stripe Live Publishable Key",
        r"pk_live_[0-9a-zA-Z]{24}",
        "high",
        "Exposed Stripe live publishable key",
    ),
    (
        "Generic API Key",
        r"(?i)api[_\-]?key[_\-]?[=:\s\"']+[0-9a-zA-Z]{16,}",
        "medium",
        "Potential API key found",
    ),
    (
        "JWT Token",
        r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*",
        "medium",
        "JWT token found in JS file",
    ),
    (
        "GitHub Personal Access Token",
        r"ghp_[0-9a-zA-Z]{36}",
        "critical",
        "Exposed GitHub personal access token",
    ),
    (
        "GitHub OAuth Token",
        r"gho_[0-9a-zA-Z]{36}",
        "critical",
        "Exposed GitHub OAuth token",
    ),
    (
        "Private/Internal URL",
        r"https?://(?:localhost|127\.0\.0\.1|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3})[:/]",
        "medium",
        "Internal/private network URL found in JS",
    ),
    (
        "Hardcoded Password",
        r"(?i)password\s*[=:]\s*[\"'][^\"']{4,}[\"']",
        "high",
        "Hardcoded password found in JS file",
    ),
    (
        "S3 Bucket URL",
        r"s3\.amazonaws\.com/[a-z0-9\-]+|[a-z0-9\-]+\.s3\.amazonaws\.com",
        "low",
        "Amazon S3 bucket reference found",
    ),
    (
        "MongoDB Connection String",
        r"mongodb://[^\s\"'<>]+",
        "critical",
        "MongoDB connection string exposed",
    ),
    (
        "PostgreSQL Connection String",
        r"postgresql://[^\s\"'<>]+",
        "critical",
        "PostgreSQL connection string exposed",
    ),
    (
        "MySQL Connection String",
        r"mysql://[^\s\"'<>]+",
        "critical",
        "MySQL connection string exposed",
    ),
    (
        "Redis Connection String",
        r"redis://[^\s\"'<>]+",
        "high",
        "Redis connection string exposed",
    ),
]

# Common JS paths to probe if no crawled URLs are available
_COMMON_JS_PATHS = [
    "/app.js",
    "/main.js",
    "/bundle.js",
    "/vendor.js",
    "/index.js",
    "/assets/js/app.js",
    "/assets/js/main.js",
    "/static/js/main.js",
    "/static/js/bundle.js",
    "/js/app.js",
    "/js/main.js",
    "/dist/bundle.js",
    "/dist/app.js",
    "/build/static/js/main.js",
]

# Minimum Shannon entropy threshold to flag a string as a potential secret
_ENTROPY_THRESHOLD = 4.5
_ENTROPY_MIN_LENGTH = 20
_ENTROPY_MAX_LENGTH = 100


def _shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of *data*."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _find_high_entropy_strings(content: str) -> List[str]:
    """Extract high-entropy strings that may be secrets."""
    # Look for quoted strings or assignment values
    candidates = re.findall(
        r"""(?:["'`])([A-Za-z0-9+/=_\-]{%d,%d})(?:["'`])""" % (_ENTROPY_MIN_LENGTH, _ENTROPY_MAX_LENGTH),
        content,
    )
    return [s for s in candidates if _shannon_entropy(s) >= _ENTROPY_THRESHOLD]


class JSSecretsModule(BaseModule):
    """Scan JavaScript files for secrets, credentials, and sensitive data."""

    name = "js_secrets"
    description = "Scans JS files for secrets: API keys, tokens, passwords, connection strings"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "secrets"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)

        general = config.general
        timeout = general.timeout
        proxy = general.proxy
        user_agents = general.user_agents

        # Collect JS URLs to scan
        js_urls = await self._collect_js_urls(target, config)

        if not js_urls:
            logger.info("No JS URLs found for %s — trying common paths", target)
            base = f"https://{target}" if not target.startswith("http") else target
            js_urls = [urljoin(base, path) for path in _COMMON_JS_PATHS]

        logger.info("JS secrets scan: checking %d JS URLs for %s", len(js_urls), target)

        async with AsyncHTTPClient(
            timeout=timeout,
            user_agents=user_agents,
            proxy=proxy,
            verify_ssl=False,
            retries=1,
        ) as http:
            sem = asyncio.Semaphore(10)

            async def _scan_one(url: str) -> List[Finding]:
                async with sem:
                    return await self._scan_js_url(http, url)

            findings_lists = await asyncio.gather(
                *[_scan_one(u) for u in js_urls],
                return_exceptions=True,
            )

        scanned = 0
        for fl in findings_lists:
            if isinstance(fl, Exception):
                logger.debug("JS scan error: %s", fl)
                continue
            scanned += 1
            result.findings.extend(fl)

        result.raw = {
            "js_urls_checked": len(js_urls),
            "js_urls_scanned": scanned,
            "total_findings": len(result.findings),
        }
        logger.info(
            "JS secrets scan complete — %d URLs scanned, %d findings",
            scanned,
            len(result.findings),
        )
        return result

    async def _collect_js_urls(self, target: str, config: Config) -> List[str]:
        """Collect JS URLs from crawl shared store if available."""
        try:
            from godrecon.modules.crawl import get_crawled_urls  # type: ignore
            urls = get_crawled_urls(target) or []
            return [u for u in urls if u.endswith(".js")]
        except (ImportError, Exception):
            return []

    async def _scan_js_url(self, http: AsyncHTTPClient, url: str) -> List[Finding]:
        """Fetch a JS file and scan it for secrets."""
        findings: List[Finding] = []
        try:
            resp = await http.get(url, allow_redirects=True)
            if not resp or resp.get("status", 0) != 200:
                return findings
            content = resp.get("body", "") or ""
            if not content or "javascript" not in resp.get("headers", {}).get("content-type", "text/javascript"):
                # Accept if no content-type check fails — still scan
                pass
            if not content:
                return findings
        except Exception as exc:
            logger.debug("Failed to fetch %s: %s", url, exc)
            return findings

        # Run regex patterns
        for pattern_name, pattern, severity, description in _SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                match_val = match if isinstance(match, str) else str(match)
                # Truncate long matches
                display = match_val[:120] + "..." if len(match_val) > 120 else match_val
                findings.append(
                    Finding(
                        title=f"{pattern_name} found in JS file",
                        description=f"{description}\nURL: {url}\nMatch: {display}",
                        severity=severity,
                        data={"url": url, "pattern": pattern_name, "match": display},
                        tags=["js-secrets", "secret", pattern_name.lower().replace(" ", "-")],
                        evidence=display,
                        source_module=self.name,
                    )
                )

        # Entropy-based detection
        high_entropy = _find_high_entropy_strings(content)
        for s in high_entropy[:20]:  # cap to avoid noise
            entropy = _shannon_entropy(s)
            findings.append(
                Finding(
                    title="High-entropy string (potential secret) in JS file",
                    description=(
                        f"High Shannon entropy string detected in JS file.\n"
                        f"URL: {url}\nEntropy: {entropy:.2f}\nValue: {s[:80]}"
                    ),
                    severity="info",
                    data={"url": url, "value": s[:80], "entropy": entropy},
                    tags=["js-secrets", "entropy", "potential-secret"],
                    evidence=s[:80],
                    source_module=self.name,
                )
            )

        return findings
