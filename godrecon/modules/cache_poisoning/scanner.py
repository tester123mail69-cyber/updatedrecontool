"""Cache poisoning scanner — tests web cache, CDN, and cache deception attacks."""

from __future__ import annotations

import asyncio
import hashlib
from typing import Dict, List, Tuple

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult

# Unkeyed header tests: (header_name, test_value, description)
_UNKEYED_HEADERS: List[Tuple[str, str, str]] = [
    ("X-Forwarded-Host", "evil.com", "Host override via X-Forwarded-Host"),
    ("X-Host", "evil.com", "Host override via X-Host"),
    ("X-Forwarded-Server", "evil.com", "Server override via X-Forwarded-Server"),
    ("X-Original-URL", "/admin", "URL override via X-Original-URL"),
    ("X-Rewrite-URL", "/admin", "URL override via X-Rewrite-URL"),
    ("X-HTTP-Method-Override", "DELETE", "Method override unkeyed"),
    ("Forwarded", "for=127.0.0.1;host=evil.com", "Forwarded header host injection"),
    ("X-Forwarded-For", "127.0.0.1", "IP spoofing via X-Forwarded-For"),
    ("CF-Connecting-IP", "127.0.0.1", "Cloudflare IP override"),
    ("True-Client-IP", "127.0.0.1", "True-Client-IP override"),
]

# Cache deception paths to test
_DECEPTION_PATHS: List[Tuple[str, str]] = [
    ("/account/profile.css", "CSS extension deception"),
    ("/api/user.jpg", "Image extension deception"),
    ("/dashboard/data.js", "JS extension deception"),
    ("/settings/export.json;.css", "Semicolon path confusion"),
    ("/profile/%0d%0a.css", "CRLF injection deception"),
]


class CachePoisoningModule(BaseModule):
    """Tests for web cache poisoning, cache deception, and CDN poisoning."""

    name = "cache_poisoning"
    description = "Cache poisoning scanner — unkeyed headers, cache deception, CDN"
    version = "1.0.0"
    category = "vuln"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        base_url = f"https://{target}" if not target.startswith("http") else target
        findings: List[Finding] = []

        tasks = [
            self._test_unkeyed_headers(base_url),
            self._test_cache_deception(base_url),
            self._test_cdn_poisoning(base_url),
            self._test_cache_key_manipulation(base_url),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return ModuleResult(module_name=self.name, target=target, findings=findings)

    async def _test_unkeyed_headers(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp

            # Get baseline response
            async with aiohttp.ClientSession() as session:
                baseline_hash = await self._get_response_hash(session, base_url, {})

                for header, value, description in _UNKEYED_HEADERS:
                    try:
                        poisoned_hash = await self._get_response_hash(
                            session, base_url, {header: value}
                        )
                        if poisoned_hash and baseline_hash and poisoned_hash != baseline_hash:
                            findings.append(Finding(
                                title=f"Cache Poisoning: Unkeyed Header {header}",
                                description=(
                                    f"{description}\n"
                                    f"Header {header}: {value} changes the response — "
                                    "may be reflected in cached content."
                                ),
                                severity="high",
                                tags=["cache_poisoning", "unkeyed_header"],
                                data={
                                    "header": header,
                                    "value": value,
                                    "url": base_url,
                                },
                            ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _get_response_hash(
        self, session: object, url: str, extra_headers: Dict[str, str]
    ) -> str:
        try:
            import aiohttp
            headers = {
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                **extra_headers,
            }
            async with session.get(  # type: ignore[attr-defined]
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False
            ) as resp:
                body = await resp.read()
                return hashlib.md5(body).hexdigest()  # noqa: S324
        except Exception:  # noqa: BLE001
            return ""

    async def _test_cache_deception(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                for path, description in _DECEPTION_PATHS:
                    url = f"{base_url}{path}"
                    try:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=8),
                            allow_redirects=False,
                        ) as resp:
                            cache_headers = {
                                k.lower(): v
                                for k, v in resp.headers.items()
                                if "cache" in k.lower() or k.lower() in ("age", "cf-cache-status", "x-cache")
                            }
                            if resp.status == 200 and cache_headers:
                                findings.append(Finding(
                                    title=f"Cache Deception Candidate: {path}",
                                    description=(
                                        f"{description}\n"
                                        f"URL {url} returned 200 with cache headers: {cache_headers}"
                                    ),
                                    severity="medium",
                                    tags=["cache_poisoning", "cache_deception"],
                                    data={"url": url, "cache_headers": cache_headers},
                                ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _test_cdn_poisoning(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            cdn_headers = [
                ("X-Forwarded-Host", "cdn-poison.evil.com"),
                ("X-Original-Host", "cdn-poison.evil.com"),
            ]
            async with aiohttp.ClientSession() as session:
                for header, value in cdn_headers:
                    url = f"{base_url}/"
                    try:
                        async with session.get(
                            url,
                            headers={header: value},
                            timeout=aiohttp.ClientTimeout(total=8),
                            allow_redirects=False,
                        ) as resp:
                            body = await resp.text()
                            if value in body or "evil.com" in body:
                                findings.append(Finding(
                                    title=f"CDN Poisoning: {header} Reflected",
                                    description=(
                                        f"Header {header}: {value} is reflected in the response body. "
                                        "May allow CDN cache poisoning."
                                    ),
                                    severity="high",
                                    tags=["cache_poisoning", "cdn_poisoning"],
                                    data={"header": header, "value": value, "url": url},
                                ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _test_cache_key_manipulation(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            # Test query string and path normalization
            variations = [
                f"{base_url}/?cachebust=1",
                f"{base_url}/?a=1&b=2",
                f"{base_url}/./",
                f"{base_url}//",
                f"{base_url}/%2F",
            ]
            async with aiohttp.ClientSession() as session:
                hashes = []
                for url in variations:
                    h = await self._get_response_hash(session, url, {})
                    if h:
                        hashes.append((url, h))

                unique_hashes = set(h for _, h in hashes)
                if len(hashes) > 1 and len(unique_hashes) < len(hashes):
                    findings.append(Finding(
                        title="Cache Key Normalization Detected",
                        description=(
                            "Multiple URL variations produce identical cached responses — "
                            "cache key normalization may be exploitable."
                        ),
                        severity="low",
                        tags=["cache_poisoning", "cache_key"],
                        data={"variations": [u for u, _ in hashes]},
                    ))
        except ImportError:
            pass
        return findings
