"""ProjectDiscovery Chaos dataset — subdomain source.

Queries the Chaos API (chaos.projectdiscovery.io) which maintains a massive
pre-collected subdomain database.  A free API key is available at
https://chaos.projectdiscovery.io.
"""

from __future__ import annotations

import json
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


class ChaosSource(SubdomainSource):
    """Fetch subdomains from the ProjectDiscovery Chaos dataset.

    Requires a free API key from https://chaos.projectdiscovery.io.
    """

    name = "chaos"
    description = "ProjectDiscovery Chaos dataset"
    requires_api_key = True
    api_key_name = "chaos"

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self.api_key = api_key

    async def fetch(self, domain: str) -> Set[str]:
        """Query the Chaos API for subdomains of *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        results: Set[str] = set()
        if not self.api_key:
            return results
        try:
            headers = {"Authorization": self.api_key}
            async with AsyncHTTPClient(timeout=30, retries=2) as client:
                resp = await client.get(url, headers=headers)
                if resp["status"] != 200:
                    return results
                data = json.loads(resp["body"])
                # Response: {"domain": "...", "subdomains": ["www", "api", ...], "count": N}
                for sub in data.get("subdomains", []):
                    sub = sub.strip().lower().lstrip("*.")
                    if not sub:
                        continue
                    fqdn = f"{sub}.{domain}" if not sub.endswith(f".{domain}") and sub != domain else sub
                    if fqdn.endswith(f".{domain}") or fqdn == domain:
                        results.add(fqdn)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Chaos error: %s", exc)
        return results
