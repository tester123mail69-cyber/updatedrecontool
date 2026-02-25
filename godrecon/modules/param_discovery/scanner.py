"""Parameter Discovery module for GODRECON.

Discovers hidden/undocumented parameters via JS mining, wordlist
brute-forcing, HTML form extraction, and URL pattern analysis.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_PROBE_VALUE = "GODRECON_TEST"

_COMMON_PARAMS = [
    "debug", "test", "admin", "id", "user", "token", "key", "secret",
    "api", "callback", "redirect", "next", "url", "src", "file", "page",
    "view", "action", "cmd", "exec", "path", "dir", "include", "mode",
    "format", "type", "lang", "locale", "q", "query", "search", "filter",
    "sort", "order", "limit", "offset", "start", "end", "from", "to",
    "name", "email", "username", "password", "pass", "pwd", "auth",
    "session", "csrf", "nonce", "ref", "referrer", "return", "back",
    "goto", "target", "dest", "destination", "forward", "location",
    "output", "data", "json", "xml", "yaml", "config", "settings",
    "env", "environment", "version", "v", "ver", "build",
]

# Regex to extract param names from JS files
_JS_PARAM_PATTERNS = [
    r"""URLSearchParams\s*\(\s*['"]\??([^'"]+)""",
    r"""[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,30})=(?:[^&\s"'<>]*)""",
    r"""(?:get|set|append|has|delete)\s*\(\s*['"]([a-zA-Z_][a-zA-Z0-9_\-]{1,30})['"]""",
    r"""(?:params|query|qs)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]{1,30})\s*=""",
]

# Regex to extract input names from HTML forms
_FORM_INPUT_RE = re.compile(r"""<input[^>]+name\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_SELECT_RE = re.compile(r"""<select[^>]+name\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_TEXTAREA_RE = re.compile(r"""<textarea[^>]+name\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


class ParamDiscoveryModule(BaseModule):
    """Discover hidden parameters via JS mining, brute-force, and HTML extraction."""

    name = "param_discovery"
    description = "Discovers hidden parameters via JS mining, wordlist brute-forcing, and HTML form extraction"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "discovery"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)

        general = config.general
        timeout = general.timeout
        proxy = general.proxy
        user_agents = general.user_agents

        base_url = f"https://{target}" if not target.startswith("http") else target

        async with AsyncHTTPClient(
            timeout=timeout,
            user_agents=user_agents,
            proxy=proxy,
            verify_ssl=False,
            retries=1,
        ) as http:
            # 1. Fetch base page and extract form params + crawled pages
            crawled_urls = await self._get_crawled_urls(target)
            pages_to_check = list({base_url} | set(crawled_urls[:20]))

            # 2. Collect params from HTML forms and JS files
            discovered_params: Set[str] = set()
            for page_url in pages_to_check:
                form_params = await self._extract_form_params(http, page_url)
                discovered_params.update(form_params)

            js_urls = [u for u in crawled_urls if u.endswith(".js")][:10]
            for js_url in js_urls:
                js_params = await self._extract_js_params(http, js_url)
                discovered_params.update(js_params)

            # 3. Combine with wordlist
            all_params = list(set(_COMMON_PARAMS) | discovered_params)
            logger.info(
                "Param discovery: testing %d params on %s", len(all_params), base_url
            )

            # 4. Brute-force and check for reflection
            sem = asyncio.Semaphore(20)

            async def _probe(param: str) -> List[Finding]:
                async with sem:
                    return await self._probe_param(http, base_url, param)

            probe_results = await asyncio.gather(
                *[_probe(p) for p in all_params],
                return_exceptions=True,
            )

        for pr in probe_results:
            if isinstance(pr, list):
                result.findings.extend(pr)

        result.raw = {
            "params_tested": len(all_params),
            "params_from_forms": list(discovered_params),
            "reflected_params": [f.data.get("param") for f in result.findings],
        }
        logger.info(
            "Param discovery complete — %d params tested, %d reflected",
            len(all_params),
            len(result.findings),
        )
        return result

    async def _get_crawled_urls(self, target: str) -> List[str]:
        """Retrieve URLs from crawl shared store if available."""
        try:
            from godrecon.modules.crawl import get_crawled_urls  # type: ignore
            return get_crawled_urls(target) or []
        except (ImportError, Exception):
            return []

    async def _extract_form_params(self, http: AsyncHTTPClient, url: str) -> Set[str]:
        """Extract parameter names from HTML forms."""
        params: Set[str] = set()
        try:
            resp = await http.get(url, allow_redirects=True)
            if not resp or resp.get("status", 0) not in (200, 301, 302):
                return params
            body = resp.get("body", "") or ""
            params.update(_FORM_INPUT_RE.findall(body))
            params.update(_SELECT_RE.findall(body))
            params.update(_TEXTAREA_RE.findall(body))
        except Exception as exc:
            logger.debug("Form extraction failed for %s: %s", url, exc)
        return params

    async def _extract_js_params(self, http: AsyncHTTPClient, url: str) -> Set[str]:
        """Extract parameter names from JavaScript files."""
        params: Set[str] = set()
        try:
            resp = await http.get(url, allow_redirects=True)
            if not resp or resp.get("status", 0) != 200:
                return params
            body = resp.get("body", "") or ""
            for pattern in _JS_PARAM_PATTERNS:
                matches = re.findall(pattern, body)
                for m in matches:
                    # Split on & in case multiple params captured
                    for part in m.split("&"):
                        name = part.split("=")[0].strip()
                        if name and re.match(r"^[a-zA-Z_][a-zA-Z0-9_\-]{0,30}$", name):
                            params.add(name)
        except Exception as exc:
            logger.debug("JS param extraction failed for %s: %s", url, exc)
        return params

    async def _probe_param(
        self, http: AsyncHTTPClient, base_url: str, param: str
    ) -> List[Finding]:
        """Send probe request and check for value reflection."""
        findings: List[Finding] = []
        probe_url = f"{base_url}?{param}={_PROBE_VALUE}"
        try:
            resp = await http.get(probe_url, allow_redirects=True)
            if not resp:
                return findings
            body = resp.get("body", "") or ""
            if _PROBE_VALUE in body:
                findings.append(
                    Finding(
                        title=f"Reflected parameter: {param}",
                        description=(
                            f"The parameter '{param}' is reflected in the response body.\n"
                            f"URL: {probe_url}\nStatus: {resp.get('status')}"
                        ),
                        severity="info",
                        data={"param": param, "url": probe_url, "status": resp.get("status")},
                        tags=["param-discovery", "reflection", "info"],
                        evidence=f"{param}={_PROBE_VALUE} reflected",
                        source_module=self.name,
                    )
                )
        except Exception as exc:
            logger.debug("Probe failed for param %s: %s", param, exc)
        return findings
