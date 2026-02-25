"""Wayback Machine deep mining module."""

from __future__ import annotations

import re
from typing import List, Set
from urllib.parse import urlparse

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult

_SENSITIVE_PATTERNS = re.compile(
    r'(?:/api/|/v\d+/|/admin|/internal|/debug|/backup|/\.git|/config|'
    r'password|secret|token|key|credential|\.env|\.sql|\.bak)',
    re.IGNORECASE,
)


class WaybackMiningModule(BaseModule):
    """Pulls historical URLs from Wayback Machine, CommonCrawl, AlienVault OTX."""

    name = "wayback_mining"
    description = "Wayback Machine deep mining for historical endpoints"
    version = "1.0.0"
    category = "recon"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        cfg = config.wayback_mining_config
        sources = cfg.sources
        findings: List[Finding] = []
        all_urls: Set[str] = set()

        if "wayback" in sources:
            urls = await self._query_wayback(target)
            all_urls.update(urls)
        if "commoncrawl" in sources:
            urls = await self._query_commoncrawl(target)
            all_urls.update(urls)
        if "otx" in sources:
            urls = await self._query_otx(target)
            all_urls.update(urls)

        for url in all_urls:
            severity = "medium" if _SENSITIVE_PATTERNS.search(url) else "info"
            findings.append(Finding(
                title=f"Historical URL: {_short(url)}",
                description=f"Historical URL discovered: {url}",
                severity=severity,
                tags=["wayback_mining", "historical"],
                data={"url": url},
            ))

        if not all_urls:
            findings.append(Finding(
                title="Wayback Mining: No historical URLs found",
                description=f"No historical URLs found for {target} from configured sources.",
                severity="info",
                tags=["wayback_mining"],
            ))

        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=findings,
            raw={"total_urls": len(all_urls)},
        )

    async def _query_wayback(self, target: str) -> Set[str]:
        urls: Set[str] = set()
        try:
            import aiohttp
            api = f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original&collapse=urlkey&limit=200"
            async with aiohttp.ClientSession() as session:
                async with session.get(api, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for row in data[1:]:  # skip header
                            if row:
                                urls.add(row[0])
        except Exception:  # noqa: BLE001
            pass
        return urls

    async def _query_commoncrawl(self, target: str) -> Set[str]:
        urls: Set[str] = set()
        try:
            import aiohttp
            api = f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url={target}/*&output=json&limit=100"
            async with aiohttp.ClientSession() as session:
                async with session.get(api, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        import json
                        for line in text.strip().splitlines():
                            try:
                                obj = json.loads(line)
                                if "url" in obj:
                                    urls.add(obj["url"])
                            except Exception:  # noqa: BLE001
                                pass
        except Exception:  # noqa: BLE001
            pass
        return urls

    async def _query_otx(self, target: str) -> Set[str]:
        urls: Set[str] = set()
        try:
            import aiohttp
            api = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/url_list?limit=100"
            async with aiohttp.ClientSession() as session:
                async with session.get(api, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("url_list", []):
                            if "url" in item:
                                urls.add(item["url"])
        except Exception:  # noqa: BLE001
            pass
        return urls


def _short(url: str) -> str:
    """Return a short path representation of a URL."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    return path[:80] if len(path) > 80 else path
