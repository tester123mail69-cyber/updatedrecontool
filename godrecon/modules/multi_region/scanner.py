"""Multi-region scanning module — detects geo-based access controls."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult

# Built-in region proxy stubs (operators configure actual proxies)
_DEFAULT_REGIONS = {
    "us-east": None,
    "eu-west": None,
    "ap-southeast": None,
}

_GEO_BLOCK_INDICATORS = [
    "not available in your country",
    "access denied",
    "geo-restricted",
    "region not supported",
    "unavailable in your region",
    "this service is not available",
    "403",
    "451",
]


class MultiRegionModule(BaseModule):
    """Scans from multiple geographic locations to detect geo-based access controls."""

    name = "multi_region"
    description = "Multi-region scanning via proxy chains — detects geo restrictions"
    version = "1.0.0"
    category = "recon"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        cfg = config.multi_region_config
        base_url = f"https://{target}" if not target.startswith("http") else target
        findings: List[Finding] = []

        proxies: Dict[str, Optional[str]] = dict(_DEFAULT_REGIONS)
        proxies.update(cfg.proxies)

        tasks = []
        for region, proxy_url in proxies.items():
            tasks.append(self._scan_region(base_url, region, proxy_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        region_responses: Dict[str, Dict[str, Any]] = {}
        for i, (region, _) in enumerate(proxies.items()):
            result = results[i]
            if isinstance(result, dict):
                region_responses[region] = result

        findings.extend(self._compare_regions(region_responses, base_url))

        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=findings,
            raw={"regions": region_responses},
        )

    async def _scan_region(
        self, url: str, region: str, proxy: Optional[str]
    ) -> Dict[str, Any]:
        try:
            import aiohttp
            connector_kwargs: Dict[str, Any] = {}
            request_kwargs: Dict[str, Any] = {"timeout": aiohttp.ClientTimeout(total=10)}
            if proxy:
                request_kwargs["proxy"] = proxy

            async with aiohttp.ClientSession(**connector_kwargs) as session:
                async with session.get(url, **request_kwargs, allow_redirects=True) as resp:
                    text = (await resp.text())[:2000]
                    return {
                        "region": region,
                        "status": resp.status,
                        "length": len(text),
                        "body_sample": text[:500],
                        "headers": dict(resp.headers),
                    }
        except Exception as e:  # noqa: BLE001
            return {"region": region, "error": str(e), "status": 0, "length": 0}

    def _compare_regions(
        self, responses: Dict[str, Dict[str, Any]], url: str
    ) -> List[Finding]:
        findings: List[Finding] = []
        if len(responses) < 2:
            findings.append(Finding(
                title="Multi-Region: Insufficient proxy regions configured",
                description="Configure proxies in multi_region_config.proxies for effective geo-testing.",
                severity="info",
                tags=["multi_region"],
            ))
            return findings

        statuses = {r: v.get("status", 0) for r, v in responses.items()}
        lengths = {r: v.get("length", 0) for r, v in responses.items()}
        bodies = {r: v.get("body_sample", "").lower() for r, v in responses.items()}

        # Detect geo-blocking
        blocked_regions = []
        for region, body in bodies.items():
            if any(indicator in body for indicator in _GEO_BLOCK_INDICATORS):
                blocked_regions.append(region)
            if statuses.get(region, 0) == 451:
                blocked_regions.append(region)

        if blocked_regions:
            findings.append(Finding(
                title=f"Geo-Blocking Detected: {', '.join(blocked_regions)}",
                description=(
                    f"Target {url} appears geo-blocked from regions: {blocked_regions}. "
                    "Content or access differs based on geographic location."
                ),
                severity="medium",
                tags=["multi_region", "geo_restriction"],
                data={"blocked_regions": blocked_regions, "statuses": statuses},
            ))

        # Detect significant response differences
        unique_statuses = set(statuses.values()) - {0}
        if len(unique_statuses) > 1:
            findings.append(Finding(
                title="Multi-Region: Different HTTP Status Codes",
                description=(
                    f"Different HTTP statuses from different regions: {statuses}. "
                    "Possible geo-based access control."
                ),
                severity="medium",
                tags=["multi_region", "geo_restriction"],
                data={"statuses": statuses},
            ))

        max_len = max(lengths.values(), default=0)
        min_len = min(lengths.values(), default=0)
        if max_len > 0 and (max_len - min_len) / max_len > 0.3:
            findings.append(Finding(
                title="Multi-Region: Response Content Differs Significantly",
                description=(
                    f"Response body lengths differ by >30% across regions: {lengths}. "
                    "Content may be geo-customized."
                ),
                severity="low",
                tags=["multi_region"],
                data={"lengths": lengths},
            ))

        return findings
