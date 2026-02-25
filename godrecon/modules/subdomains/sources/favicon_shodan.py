"""Favicon hash matching via Shodan — subdomain discovery through infrastructure fingerprinting.

Computes the MurmurHash3 of the target's favicon and searches Shodan for
other hosts serving the same favicon.  This can reveal hidden subdomains and
related infrastructure not listed in any DNS source.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from typing import Set

from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.modules.subdomains.sources.base import SubdomainSource


def _mmh3_hash(data: bytes) -> int:
    """Compute the MurmurHash3 (32-bit) of *data* — matches Shodan's favicon hash algorithm.

    Uses the ``mmh3`` package when available, falls back to a pure-Python
    implementation otherwise.

    Args:
        data: Raw bytes to hash.

    Returns:
        Signed 32-bit MurmurHash3 value.
    """
    try:
        import mmh3
        return mmh3.hash(data)
    except ImportError:
        pass
    # Pure-Python fallback
    seed = 0
    length = len(data)
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h1 = seed

    num_blocks = length // 4
    for block_start in range(0, num_blocks * 4, 4):
        k1 = struct.unpack_from("<I", data, block_start)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail_index = num_blocks * 4
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= data[tail_index + 2] << 16
    if tail_size >= 2:
        k1 ^= data[tail_index + 1] << 8
    if tail_size >= 1:
        k1 ^= data[tail_index]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


class FaviconShodanSource(SubdomainSource):
    """Discover related subdomains via Shodan favicon hash search.

    Downloads the target's ``/favicon.ico``, computes the MurmurHash3,
    then queries Shodan for other hosts with the same favicon hash.
    Requires a Shodan API key.
    """

    name = "favicon_shodan"
    description = "Shodan favicon hash matching (active)"
    requires_api_key = True
    api_key_name = "shodan"

    def __init__(self, api_key: str) -> None:
        super().__init__()
        self.api_key = api_key

    async def fetch(self, domain: str) -> Set[str]:
        """Find subdomains via Shodan favicon hash for *domain*.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        if not self.api_key:
            return results
        try:
            async with AsyncHTTPClient(timeout=15, retries=1) as client:
                # Download the favicon
                favicon_url = f"https://{domain}/favicon.ico"
                resp = await client.get(favicon_url)
                if resp["status"] != 200 or not resp.get("body"):
                    return results

                favicon_bytes = resp["body"]
                if isinstance(favicon_bytes, str):
                    favicon_bytes = favicon_bytes.encode("latin-1")

                # Encode as base64 with line endings (Shodan's format)
                b64 = base64.encodebytes(favicon_bytes).decode()
                favicon_hash = _mmh3_hash(b64.encode())

                # Query Shodan for hosts with this favicon hash
                shodan_url = (
                    f"https://api.shodan.io/shodan/host/search"
                    f"?key={self.api_key}"
                    f"&query=http.favicon.hash:{favicon_hash}"
                    f"&facets=hostnames"
                )
                search_resp = await client.get(shodan_url)
                if search_resp["status"] != 200:
                    return results

                data = json.loads(search_resp["body"])
                for match in data.get("matches", []):
                    for hostname in match.get("hostnames", []):
                        hostname = hostname.lower().strip()
                        if hostname.endswith(f".{domain}") or hostname == domain:
                            results.add(hostname)
                    # Also check SSL cert hostnames
                    ssl_info = match.get("ssl", {})
                    cert = ssl_info.get("cert", {}) if isinstance(ssl_info, dict) else {}
                    for name in cert.get("extensions", {}).get("subjectAltName", "").split(","):
                        name = name.strip().lstrip("DNS:").lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            results.add(name.lower())
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("Favicon Shodan error: %s", exc)
        return results
