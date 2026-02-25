"""Subfinder (ProjectDiscovery) external tool wrapper.

Runs ``subfinder`` as a subprocess if the binary is available on PATH.
Subfinder is a fast passive subdomain enumeration tool that aggregates
results from numerous sources.  Install via:
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Set

from godrecon.modules.subdomains.sources.base import SubdomainSource


class SubfinderSource(SubdomainSource):
    """Run the ``subfinder`` binary to enumerate subdomains.

    Silently skipped if the binary is not found on PATH.
    """

    name = "subfinder"
    description = "ProjectDiscovery Subfinder (external binary)"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Run subfinder and parse its output for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        if not shutil.which("subfinder"):
            self.logger.debug("subfinder binary not found — skipping")
            return results
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder",
                "-d", domain,
                "-silent",
                "-all",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            for line in stdout.decode(errors="replace").splitlines():
                sub = line.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    results.add(sub)
        except asyncio.TimeoutError:
            self.logger.debug("subfinder timed out for %s", domain)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("subfinder error: %s", exc)
        return results
