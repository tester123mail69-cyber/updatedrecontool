"""NOERROR-based DNS enumeration — active subdomain discovery.

Some DNS servers return NOERROR (rcode 0) for subdomains that exist in DNS
even when there is no A/AAAA record.  This is distinct from NXDOMAIN (rcode 3)
which indicates the name does not exist at all.  By querying ANY record type
and checking for NOERROR vs NXDOMAIN, hidden subdomains can be found that
would be missed by a pure A-record brute-force.
"""

from __future__ import annotations

import asyncio
import random
import socket
import struct
from typing import List, Optional, Set

from godrecon.modules.subdomains.sources.base import SubdomainSource
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Common subdomain prefixes to probe in NOERROR mode
_NOERROR_WORDLIST: List[str] = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "mx", "mx1",
    "mx2", "vpn", "remote", "webmail", "admin", "portal", "api", "dev",
    "staging", "test", "uat", "qa", "beta", "alpha", "demo", "sandbox",
    "cdn", "static", "media", "assets", "img", "images", "video", "dl",
    "download", "files", "docs", "support", "help", "kb", "wiki",
    "git", "gitlab", "github", "jenkins", "jira", "confluence", "sonar",
    "grafana", "kibana", "elastic", "search", "monitor", "metrics",
    "app", "apps", "mobile", "m", "wap", "web", "www2", "www3",
    "auth", "login", "oauth", "sso", "idp", "ldap", "ad",
    "db", "database", "mysql", "postgres", "redis", "cache", "memcache",
    "internal", "intranet", "private", "corp", "corporate",
    "backup", "bak", "old", "legacy", "archive",
    "shop", "store", "cart", "pay", "payment", "billing",
    "blog", "news", "forum", "community", "social",
    "api2", "api3", "v1", "v2", "v3", "graphql",
    "status", "health", "uptime", "ping",
    "mail2", "email", "lists", "newsletter",
    "cloud", "s3", "storage", "bucket",
    "ops", "devops", "infra", "infrastructure",
]

_DNS_PORT = 53
_NOERROR = 0
_NXDOMAIN = 3


async def _dns_query_noerror(
    host: str,
    nameserver: str = "8.8.8.8",
    timeout: float = 3.0,
) -> Optional[int]:
    """Send a minimal DNS ANY query and return the response RCODE.

    Args:
        host: Fully-qualified hostname to query.
        nameserver: Resolver IP address.
        timeout: Query timeout in seconds.

    Returns:
        DNS RCODE integer, or ``None`` on network error.
    """
    # Build a minimal DNS query for type ANY (255)
    qid = random.randint(0, 65535)
    flags = 0x0100  # RD set
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)

    qname = b""
    for label in host.rstrip(".").split("."):
        enc = label.encode("ascii")
        qname += bytes([len(enc)]) + enc
    qname += b"\x00"

    question = struct.pack(">HH", 255, 1)  # QTYPE=ANY, QCLASS=IN
    query = header + qname + question

    loop = asyncio.get_event_loop()
    try:
        transport, protocol = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: _UDPProtocol(qid),
                remote_addr=(nameserver, _DNS_PORT),
            ),
            timeout=timeout,
        )
        transport.sendto(query)
        rcode = await asyncio.wait_for(protocol.result, timeout=timeout)
        transport.close()
        return rcode
    except Exception:  # noqa: BLE001
        return None


class _UDPProtocol(asyncio.DatagramProtocol):
    """Minimal asyncio UDP protocol to receive a single DNS response."""

    def __init__(self, expected_id: int) -> None:
        self.expected_id = expected_id
        self.result: asyncio.Future[int] = asyncio.get_event_loop().create_future()

    def datagram_received(self, data: bytes, addr: object) -> None:
        if len(data) < 4:
            return
        resp_id = struct.unpack(">H", data[:2])[0]
        if resp_id != self.expected_id:
            return
        rcode = data[3] & 0x0F
        if not self.result.done():
            self.result.set_result(rcode)

    def error_received(self, exc: Exception) -> None:
        if not self.result.done():
            self.result.set_exception(exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if not self.result.done():
            self.result.set_exception(ConnectionResetError("connection lost"))


class NoErrorEnumSource(SubdomainSource):
    """NOERROR vs NXDOMAIN DNS enumeration to find hidden subdomains.

    Probes common subdomain prefixes using DNS ANY queries and keeps those
    that return NOERROR even if they have no A record.  No API key required.
    """

    name = "noerror_enum"
    description = "NOERROR DNS enumeration (active)"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Enumerate subdomains via NOERROR/NXDOMAIN DNS differentiation.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        nameserver = "8.8.8.8"

        # Detect wildcard: if a random subdomain returns NOERROR, skip
        random_sub = f"_rand{random.randint(100000, 999999)}.{domain}"
        wc_rcode = await _dns_query_noerror(random_sub, nameserver)
        if wc_rcode == _NOERROR:
            self.logger.debug(
                "Wildcard NOERROR detected for %s — skipping noerror_enum", domain
            )
            return results

        semaphore = asyncio.Semaphore(50)

        async def _check(prefix: str) -> None:
            async with semaphore:
                host = f"{prefix}.{domain}"
                rcode = await _dns_query_noerror(host, nameserver)
                if rcode == _NOERROR:
                    results.add(host.lower())

        await asyncio.gather(
            *[asyncio.create_task(_check(p)) for p in _NOERROR_WORDLIST],
            return_exceptions=True,
        )
        return results
