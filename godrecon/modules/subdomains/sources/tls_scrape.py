"""TLS/SSL certificate SAN scraping — active subdomain discovery.

Connects to discovered IP addresses on common HTTPS ports and extracts
Subject Alternative Names (SANs) from their TLS certificates.  Subdomains
found this way are often not listed in any passive source.
"""

from __future__ import annotations

import asyncio
import ssl
import socket
from typing import Set

from godrecon.modules.subdomains.sources.base import SubdomainSource

_HTTPS_PORTS = [443, 8443, 4443, 10443]


class TLSScrapeSource(SubdomainSource):
    """Extract subdomains from TLS certificate SANs.

    Resolves the target domain to its IP addresses, then connects on
    common HTTPS ports and reads the Subject Alternative Names from the
    presented TLS certificate.  No API key required.
    """

    name = "tls_scrape"
    description = "TLS/SSL certificate SAN extraction (active)"
    requires_api_key = False

    async def fetch(self, domain: str) -> Set[str]:
        """Extract subdomains from TLS certificates for *domain* IPs.

        Args:
            domain: Root domain to enumerate.

        Returns:
            Set of discovered subdomain strings.
        """
        results: Set[str] = set()
        try:
            # Resolve the domain to IPs
            loop = asyncio.get_event_loop()
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(domain, 443, type=socket.SOCK_STREAM),
                    timeout=10,
                )
            except Exception:  # noqa: BLE001
                return results

            ips: Set[str] = {info[4][0] for info in infos}

            tasks = [
                asyncio.create_task(self._scrape_cert(ip, port, domain, results))
                for ip in ips
                for port in _HTTPS_PORTS
            ]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as exc:  # noqa: BLE001
            self.logger.debug("TLS scrape error: %s", exc)
        return results

    async def _scrape_cert(
        self,
        ip: str,
        port: int,
        domain: str,
        results: Set[str],
    ) -> None:
        """Connect to *ip*:*port* and extract SANs from the TLS certificate.

        Args:
            ip: IP address to connect to.
            port: TCP port to connect on.
            domain: Root domain for filtering SANs.
            results: Mutable set to add discovered subdomains into.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=domain),
                timeout=8,
            )
            cert = writer.get_extra_info("ssl_object")
            if cert:
                der = cert.getpeercert(binary_form=True)
                if der:
                    self._extract_sans(der, domain, results)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _extract_sans(der_cert: bytes, domain: str, results: Set[str]) -> None:
        """Parse a DER-encoded certificate and extract SANs for *domain*.

        Uses Python's built-in ``ssl`` module to decode the certificate.

        Args:
            der_cert: DER-encoded X.509 certificate bytes.
            domain: Root domain to filter.
            results: Mutable set to add discovered subdomains into.
        """
        try:
            pem = ssl.DER_cert_to_PEM_cert(der_cert)
            cert_dict = ssl.PEM_cert_to_DER_cert(pem)
            # Use cryptography library if available for richer parsing
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                for name in san_ext.value.get_values_for_type(x509.DNSName):
                    name = name.lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        results.add(name)
            except ImportError:
                # Fall back to loading via ssl module's DER→PEM and regex
                import re
                text = pem
                for match in re.finditer(r"DNS:([^\s,\"]+)", text):
                    name = match.group(1).lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        results.add(name)
        except Exception:  # noqa: BLE001
            pass
