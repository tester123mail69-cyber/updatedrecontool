"""Supply Chain Analysis module for GODRECON.

Detects third-party JavaScript libraries, checks for missing Subresource
Integrity (SRI) attributes, and flags known vulnerable library versions.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Library detection: (library_name, regex_pattern)
_LIBRARY_PATTERNS: List[Tuple[str, str]] = [
    ("jQuery", r"jquery[.\-](\d+\.\d+\.?\d*)(\.min)?\.js"),
    ("Bootstrap", r"bootstrap[.\-](\d+\.\d+\.?\d*)(\.min)?\.js"),
    ("React", r"react[.\-](\d+\.\d+\.?\d*)(\.min)?\.js"),
    ("Angular", r"angular[.\-](\d+\.\d+\.?\d*)(\.min)?\.js"),
    ("Vue.js", r"vue[.\-](\d+\.\d+\.?\d*)(\.min)?\.js"),
    ("Lodash", r"lodash[.\-](\d+\.\d+\.?\d*)(\.min)?\.js"),
    ("Underscore", r"underscore[.\-](\d+\.\d+\.?\d*)(\.min)?\.js"),
    ("Moment.js", r"moment[.\-](\d+\.\d+\.?\d*)(\.min)?\.js"),
    ("Axios", r"axios[.\-](\d+\.\d+\.?\d*)(\.min)?\.js"),
    ("D3.js", r"d3[.\-]v?(\d+\.\d+\.?\d*)(\.min)?\.js"),
]

# Known vulnerable version rules: (library, operator, version, severity, description)
# "lt" = library_version < threshold_version
_KNOWN_VULNERABLE: List[Dict[str, Any]] = [
    {
        "library": "jQuery",
        "threshold": (3, 0, 0),
        "severity": "high",
        "description": "jQuery < 3.0.0 is vulnerable to XSS via jQuery.htmlPrefilter (CVE-2020-11022, CVE-2020-11023)",
        "cve": "CVE-2020-11022",
    },
    {
        "library": "Bootstrap",
        "threshold": (3, 4, 1),
        "severity": "medium",
        "description": "Bootstrap < 3.4.1 is vulnerable to XSS in data-target attribute (CVE-2019-8331)",
        "cve": "CVE-2019-8331",
    },
    {
        "library": "Angular",
        "threshold": (1, 8, 0),
        "severity": "high",
        "description": "AngularJS < 1.8.0 has various XSS and CSRF vulnerabilities",
        "cve": "CVE-2020-7676",
    },
    {
        "library": "Lodash",
        "threshold": (4, 17, 21),
        "severity": "high",
        "description": "Lodash < 4.17.21 is vulnerable to prototype pollution (CVE-2021-23337, CVE-2020-28500)",
        "cve": "CVE-2021-23337",
    },
    {
        "library": "Moment.js",
        "threshold": (2, 29, 4),
        "severity": "medium",
        "description": "Moment.js < 2.29.4 is vulnerable to ReDoS (CVE-2022-24785)",
        "cve": "CVE-2022-24785",
    },
]

# CDN hostnames to flag external scripts
_CDN_HOSTS = [
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
    "code.jquery.com", "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "unpkg.com", "cdn.skypack.dev",
]

# Regex patterns for external script/link tags
_SCRIPT_TAG_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>""", re.IGNORECASE
)
_SCRIPT_INTEGRITY_RE = re.compile(r"""integrity\s*=\s*["'][^"']+["']""", re.IGNORECASE)
_LINK_TAG_RE = re.compile(
    r"""<link[^>]+href\s*=\s*["']([^"']+\.css[^"']*)["'][^>]*>""", re.IGNORECASE
)
_LINK_INTEGRITY_RE = re.compile(r"""integrity\s*=\s*["'][^"']+["']""", re.IGNORECASE)


def _parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string into a comparable tuple."""
    parts = re.findall(r"\d+", version_str)
    return tuple(int(p) for p in parts[:3]) if parts else (0, 0, 0)


def _is_vulnerable(version: Tuple[int, ...], threshold: Tuple[int, int, int]) -> bool:
    """Return True if *version* is below *threshold*."""
    return version < threshold


class SupplyChainModule(BaseModule):
    """Detect third-party JS libraries and check for vulnerable versions and missing SRI."""

    name = "supply_chain"
    description = "Detects third-party libraries, checks SRI attributes, and flags known vulnerable versions"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "supply-chain"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)

        general = config.general
        timeout = general.timeout
        proxy = general.proxy
        user_agents = general.user_agents

        base_url = f"https://{target}" if not target.startswith("http") else target

        # Get pages to analyse
        pages = await self._get_pages(target, base_url)

        async with AsyncHTTPClient(
            timeout=timeout,
            user_agents=user_agents,
            proxy=proxy,
            verify_ssl=False,
            retries=1,
        ) as http:
            sem = asyncio.Semaphore(5)

            async def _analyse(url: str) -> List[Finding]:
                async with sem:
                    return await self._analyse_page(http, url)

            page_results = await asyncio.gather(
                *[_analyse(p) for p in pages],
                return_exceptions=True,
            )

        libraries_found: List[Dict[str, Any]] = []
        for pr in page_results:
            if isinstance(pr, list):
                result.findings.extend(pr)
                for f in pr:
                    if "library" in f.data:
                        libraries_found.append(f.data["library"])

        result.raw = {
            "pages_analysed": len(pages),
            "total_findings": len(result.findings),
            "libraries_found": libraries_found,
        }
        logger.info(
            "Supply chain analysis complete — %d pages, %d findings",
            len(pages),
            len(result.findings),
        )
        return result

    async def _get_pages(self, target: str, base_url: str) -> List[str]:
        """Collect pages from crawl store or fall back to base URL."""
        try:
            from godrecon.modules.crawl import get_crawled_urls  # type: ignore
            urls = get_crawled_urls(target) or []
            html_urls = [u for u in urls if not u.endswith((".js", ".css", ".png", ".jpg"))]
            return html_urls[:20] if html_urls else [base_url]
        except (ImportError, Exception):
            return [base_url]

    async def _analyse_page(self, http: AsyncHTTPClient, url: str) -> List[Finding]:
        """Analyse a single page for supply chain issues."""
        findings: List[Finding] = []
        try:
            resp = await http.get(url, allow_redirects=True)
            if not resp or resp.get("status", 0) not in (200,):
                return findings
            body = resp.get("body", "") or ""
        except Exception as exc:
            logger.debug("Supply chain fetch failed for %s: %s", url, exc)
            return findings

        # Find all script tags
        script_tags_raw = re.findall(
            r"""(<script[^>]+src\s*=\s*["'][^"']+["'][^>]*>)""", body, re.IGNORECASE
        )

        for tag in script_tags_raw:
            src_match = re.search(r"""src\s*=\s*["']([^"']+)["']""", tag, re.IGNORECASE)
            if not src_match:
                continue
            src = src_match.group(1)

            # Library version detection
            for lib_name, lib_pattern in _LIBRARY_PATTERNS:
                m = re.search(lib_pattern, src, re.IGNORECASE)
                if m:
                    version_str = m.group(1)
                    version_tuple = _parse_version(version_str)
                    # Check against known vulnerable versions
                    for vuln in _KNOWN_VULNERABLE:
                        if vuln["library"].lower() == lib_name.lower():
                            if _is_vulnerable(version_tuple, vuln["threshold"]):
                                findings.append(
                                    Finding(
                                        title=f"Vulnerable library: {lib_name} {version_str}",
                                        description=(
                                            f"{vuln['description']}\n"
                                            f"Detected version: {version_str}\n"
                                            f"URL: {url}\nScript src: {src}"
                                        ),
                                        severity=vuln["severity"],
                                        data={
                                            "library": {"name": lib_name, "version": version_str},
                                            "url": url,
                                            "src": src,
                                            "cve": vuln.get("cve", ""),
                                        },
                                        tags=[
                                            "supply-chain",
                                            "vulnerable-library",
                                            lib_name.lower(),
                                            vuln.get("cve", "").lower(),
                                        ],
                                        evidence=f"{lib_name} {version_str}",
                                        source_module=self.name,
                                    )
                                )
                    break

            # SRI check for external scripts from CDNs
            is_external = src.startswith("http") and any(cdn in src for cdn in _CDN_HOSTS)
            has_integrity = bool(re.search(r"""integrity\s*=\s*["'][^"']+["']""", tag, re.IGNORECASE))
            if is_external and not has_integrity:
                findings.append(
                    Finding(
                        title=f"Missing SRI on external script: {src[:80]}",
                        description=(
                            f"External script loaded without Subresource Integrity (SRI) check.\n"
                            f"Page: {url}\nScript: {src}\n\n"
                            f"Add integrity and crossorigin attributes to protect against CDN compromise."
                        ),
                        severity="medium",
                        data={"url": url, "src": src, "issue": "missing_sri"},
                        tags=["supply-chain", "sri", "missing-integrity"],
                        evidence=tag[:200],
                        source_module=self.name,
                    )
                )

        # Check external CSS link tags for SRI
        link_tags_raw = re.findall(
            r"""(<link[^>]+href\s*=\s*["'][^"']+\.css[^"']*["'][^>]*>)""", body, re.IGNORECASE
        )
        for tag in link_tags_raw:
            href_match = re.search(r"""href\s*=\s*["']([^"']+)["']""", tag, re.IGNORECASE)
            if not href_match:
                continue
            href = href_match.group(1)
            is_external = href.startswith("http") and any(cdn in href for cdn in _CDN_HOSTS)
            has_integrity = bool(re.search(r"""integrity\s*=\s*["'][^"']+["']""", tag, re.IGNORECASE))
            if is_external and not has_integrity:
                findings.append(
                    Finding(
                        title=f"Missing SRI on external stylesheet: {href[:80]}",
                        description=(
                            f"External stylesheet loaded without Subresource Integrity (SRI) check.\n"
                            f"Page: {url}\nStylesheet: {href}"
                        ),
                        severity="low",
                        data={"url": url, "href": href, "issue": "missing_sri_css"},
                        tags=["supply-chain", "sri", "missing-integrity", "css"],
                        source_module=self.name,
                    )
                )

        return findings
