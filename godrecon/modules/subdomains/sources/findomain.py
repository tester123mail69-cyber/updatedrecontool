"""Findomain external tool wrapper.

Runs ``findomain`` as a subprocess if the binary is available on PATH.
Findomain is a fast cross-platform subdomain enumerator.  Install via:
  https://github.com/findomain/findomain/releases
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Set

from godrecon.modules.subdomains.sources.base import SubdomainSource


class FindomainSource(SubdomainSource):
    """Run the ``findomain`` binary to enumerate subdomains.

    Silently skipped if the binary is not found on PATH.
    """

    name = "findomain"
    description = "Findomain cross-platform enumerator (external binary)"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Run findomain and parse its output for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        if not shutil.which("findomain"):
            self.logger.debug("findomain binary not found — skipping")
            return results
        try:
            proc = await asyncio.create_subprocess_exec(
                "findomain",
                "--target", domain,
                "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            for line in stdout.decode(errors="replace").splitlines():
                sub = line.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    results.add(sub)
        except asyncio.TimeoutError:
            self.logger.debug("findomain timed out for %s", domain)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("findomain error: %s", exc)
        return results
