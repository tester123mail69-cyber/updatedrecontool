"""Subdomain permutation engine — generates and resolves permuted subdomains."""

from __future__ import annotations

import asyncio
import socket
from itertools import product
from typing import List, Set

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult

_DEFAULT_PATTERNS = ["dev", "staging", "test", "api", "admin", "internal", "uat",
                     "preprod", "qa", "beta", "v2", "v1", "app", "web", "static"]
_SEPARATORS = ["-", "."]


def _generate_permutations(domain: str, patterns: List[str], depth: int) -> Set[str]:
    """Generate subdomain permutations."""
    parts = domain.split(".")
    base = parts[0]
    tld = ".".join(parts[1:])

    candidates: Set[str] = set()
    for p in patterns:
        for sep in _SEPARATORS:
            candidates.add(f"{p}{sep}{base}.{tld}")
            candidates.add(f"{base}{sep}{p}.{tld}")
        if depth >= 2:
            for p2 in patterns[:5]:
                candidates.add(f"{p}-{p2}.{tld}")
    return candidates


async def _resolve(hostname: str) -> bool:
    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, hostname),
            timeout=3.0,
        )
        return True
    except Exception:  # noqa: BLE001
        return False


class SubdomainPermutationModule(BaseModule):
    """Generates and DNS-resolves subdomain permutations."""

    name = "subdomain_permutation"
    description = "Subdomain permutation engine with DNS resolution"
    version = "1.0.0"
    category = "recon"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        cfg = config.subdomain_permutation_config
        patterns = cfg.patterns if cfg.patterns else _DEFAULT_PATTERNS
        depth = cfg.depth

        candidates = _generate_permutations(target, patterns, depth)
        findings: List[Finding] = []

        sem = asyncio.Semaphore(50)

        async def check(host: str) -> None:
            async with sem:
                if await _resolve(host):
                    findings.append(Finding(
                        title=f"Subdomain Permutation Found: {host}",
                        description=f"Permuted subdomain {host} resolves via DNS.",
                        severity="info",
                        tags=["subdomain", "permutation", "dns"],
                        data={"subdomain": host},
                    ))

        await asyncio.gather(*[check(h) for h in candidates])

        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=findings,
            raw={"candidates_tested": len(candidates)},
        )
