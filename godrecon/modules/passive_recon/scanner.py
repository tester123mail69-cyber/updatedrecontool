"""Passive reconnaissance module — gathers data without touching the target."""

from __future__ import annotations

import asyncio
from typing import List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult


class PassiveReconModule(BaseModule):
    """Passive recon using Shodan, Censys, SecurityTrails, VirusTotal."""

    name = "passive_recon"
    description = "Passive reconnaissance without direct target contact"
    version = "1.0.0"
    category = "recon"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        findings: List[Finding] = []
        raw = {}

        keys = config.api_keys

        if keys.shodan:
            findings.extend(await self._query_shodan(target, keys.shodan))
        if keys.censys_id and keys.censys_secret:
            findings.extend(await self._query_censys(target, keys.censys_id, keys.censys_secret))
        if keys.securitytrails:
            findings.extend(await self._query_securitytrails(target, keys.securitytrails))
        if keys.virustotal:
            findings.extend(await self._query_virustotal(target, keys.virustotal))

        if not findings:
            findings.append(Finding(
                title="Passive Recon Complete",
                description="No API keys configured; skipped external passive recon sources.",
                severity="info",
                tags=["passive_recon"],
            ))

        return ModuleResult(module_name=self.name, target=target, findings=findings, raw=raw)

    async def _query_shodan(self, target: str, api_key: str) -> List[Finding]:
        try:
            import shodan  # type: ignore
            api = shodan.Shodan(api_key)
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, api.search, f"hostname:{target}")
            findings = []
            for match in results.get("matches", [])[:10]:
                findings.append(Finding(
                    title=f"Shodan: Open port {match.get('port')} on {match.get('ip_str')}",
                    description=str(match.get("data", ""))[:500],
                    severity="info",
                    tags=["passive_recon", "shodan"],
                    data={"port": match.get("port"), "ip": match.get("ip_str")},
                ))
            return findings
        except Exception:  # noqa: BLE001
            return []

    async def _query_censys(self, target: str, api_id: str, api_secret: str) -> List[Finding]:
        try:
            import censys.search  # type: ignore
            h = censys.search.CensysHosts(api_id=api_id, api_secret=api_secret)
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, lambda: list(h.search(f"dns.reverse_dns.reverse_dns:{target}", per_page=5)))
            findings = []
            for hit in results[:5]:
                findings.append(Finding(
                    title=f"Censys: Host {hit.get('ip', 'unknown')}",
                    description=f"Services: {hit.get('services', [])}",
                    severity="info",
                    tags=["passive_recon", "censys"],
                    data=hit,
                ))
            return findings
        except Exception:  # noqa: BLE001
            return []

    async def _query_securitytrails(self, target: str, api_key: str) -> List[Finding]:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
                async with session.get(url, headers={"APIKEY": api_key}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        subs = data.get("subdomains", [])[:20]
                        return [Finding(
                            title=f"SecurityTrails: Subdomain {s}.{target}",
                            description="Discovered via SecurityTrails passive DNS",
                            severity="info",
                            tags=["passive_recon", "securitytrails", "subdomain"],
                            data={"subdomain": f"{s}.{target}"},
                        ) for s in subs]
        except Exception:  # noqa: BLE001
            pass
        return []

    async def _query_virustotal(self, target: str, api_key: str) -> List[Finding]:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"https://www.virustotal.com/api/v3/domains/{target}/subdomains"
                async with session.get(url, headers={"x-apikey": api_key}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get("data", [])[:10]
                        return [Finding(
                            title=f"VirusTotal: Subdomain {item['id']}",
                            description="Discovered via VirusTotal passive DNS",
                            severity="info",
                            tags=["passive_recon", "virustotal", "subdomain"],
                            data={"subdomain": item["id"]},
                        ) for item in items]
        except Exception:  # noqa: BLE001
            pass
        return []
