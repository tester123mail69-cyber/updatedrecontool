"""P2 — GraphQL Injection detector."""

from __future__ import annotations

import re
from typing import Any, List
from urllib.parse import urlparse, urljoin

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query"]

_INTROSPECTION_QUERY = '{"query": "{ __schema { types { name } } }"}'

_GRAPHQL_ERROR_PATTERNS = [
    r'"errors"',
    r"graphql",
    r"syntax error",
    r"Cannot query field",
    r"__schema",
    r"__typename",
]

_GRAPHQL_INJECTION_PAYLOADS = [
    '{"query": "{ __typename }"}',
    '{"query": "query { __schema { queryType { name } } }"}',
]


class GraphQLInjectionDetector:
    """Detects GraphQL endpoints and injection vulnerabilities."""

    def __init__(
        self,
        http_client: Any,
        safe_mode: bool = True,
        max_payloads: int = 10,
    ) -> None:
        self.http = http_client
        self.safe_mode = safe_mode
        self.max_payloads = max_payloads

    async def scan(self, url: str, params: List[str]) -> List[Finding]:
        """Detect GraphQL endpoints and test for introspection/injection."""
        findings: List[Finding] = []

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Probe known GraphQL paths
        for path in _GRAPHQL_PATHS:
            target_url = urljoin(base, path)
            try:
                headers = {"Content-Type": "application/json"}
                resp = await self.http.post(
                    target_url, data=_INTROSPECTION_QUERY, headers=headers
                )
                if not resp:
                    continue
                body = resp.get("body", "") or ""
                status = resp.get("status_code", 0)

                if status not in (200, 201):
                    continue

                # Check if introspection is enabled
                if "__schema" in body and "types" in body:
                    findings.append(Finding(
                        title=f"GraphQL Introspection Enabled — {target_url}",
                        description=(
                            "GraphQL introspection is enabled, exposing the full schema. "
                            "This can aid attackers in understanding the API structure."
                        ),
                        severity="high",
                        confidence=0.95,
                        data={"url": target_url, "method": "POST"},
                        tags=["graphql", "p2", "high", "introspection"],
                        evidence="GraphQL __schema introspection query returned schema data",
                    ))

                # Check for generic GraphQL error patterns indicating endpoint exists
                elif any(re.search(p, body, re.I) for p in _GRAPHQL_ERROR_PATTERNS):
                    findings.append(Finding(
                        title=f"GraphQL Endpoint Detected — {target_url}",
                        description=(
                            "A GraphQL endpoint was detected. "
                            "Test for injection, introspection, and authorization issues."
                        ),
                        severity="high",
                        confidence=0.7,
                        data={"url": target_url, "method": "POST"},
                        tags=["graphql", "p2", "high"],
                        evidence="GraphQL indicators found in response body",
                    ))
            except Exception as exc:
                logger.debug("GraphQL probe error for %s: %s", target_url, exc)

        # Test injection payloads on the provided URL
        for payload in _GRAPHQL_INJECTION_PAYLOADS[: self.max_payloads]:
            try:
                headers = {"Content-Type": "application/json"}
                resp = await self.http.post(url, data=payload, headers=headers)
                if not resp:
                    continue
                body = resp.get("body", "") or ""
                if "__typename" in body or "__schema" in body:
                    findings.append(Finding(
                        title=f"GraphQL Injection — {url}",
                        description=(
                            f"GraphQL query injection succeeded at '{url}'. "
                            f"Payload: {payload}"
                        ),
                        severity="high",
                        confidence=0.85,
                        data={"url": url, "payload": payload, "method": "POST"},
                        tags=["graphql", "p2", "high", "injection"],
                        evidence="GraphQL query response returned expected fields",
                    ))
                    break
            except Exception as exc:
                logger.debug("GraphQL injection scan error: %s", exc)

        return findings
