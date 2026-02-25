"""Amass (OWASP) external tool wrapper.

Runs ``amass`` in passive enumeration mode if the binary is available on PATH.
Amass is a comprehensive attack surface management tool.  Install via:
  go install -v github.com/owasp-amass/amass/v4/...@master
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Set

from godrecon.modules.subdomains.sources.base import SubdomainSource


class AmassSource(SubdomainSource):
    """Run the ``amass`` binary in passive mode to enumerate subdomains.

    Silently skipped if the binary is not found on PATH.
    """

    name = "amass"
    description = "OWASP Amass passive enumeration (external binary)"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Run amass in passive mode and parse output for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        if not shutil.which("amass"):
            self.logger.debug("amass binary not found — skipping")
            return results
        try:
            proc = await asyncio.create_subprocess_exec(
                "amass", "enum",
                "-passive",
                "-d", domain,
                "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            for line in stdout.decode(errors="replace").splitlines():
                sub = line.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    results.add(sub)
        except asyncio.TimeoutError:
            self.logger.debug("amass timed out for %s", domain)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("amass error: %s", exc)
        return results
