"""Assetfinder (Tomnomnom) external tool wrapper.

Runs ``assetfinder`` as a subprocess if the binary is available on PATH.
Assetfinder finds domains and subdomains related to a target.  Install via:
  go install github.com/tomnomnom/assetfinder@latest
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Set

from godrecon.modules.subdomains.sources.base import SubdomainSource


class AssetfinderSource(SubdomainSource):
    """Run the ``assetfinder`` binary to enumerate subdomains.

    Silently skipped if the binary is not found on PATH.
    """

    name = "assetfinder"
    description = "Tomnomnom Assetfinder (external binary)"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Run assetfinder and parse its output for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        if not shutil.which("assetfinder"):
            self.logger.debug("assetfinder binary not found — skipping")
            return results
        try:
            proc = await asyncio.create_subprocess_exec(
                "assetfinder",
                "--subs-only",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            for line in stdout.decode(errors="replace").splitlines():
                sub = line.strip().lower().lstrip("*.")
                if sub.endswith(f".{domain}") or sub == domain:
                    results.add(sub)
        except asyncio.TimeoutError:
            self.logger.debug("assetfinder timed out for %s", domain)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("assetfinder error: %s", exc)
        return results
