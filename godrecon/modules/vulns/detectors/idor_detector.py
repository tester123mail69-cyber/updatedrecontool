"""P2 — Insecure Direct Object Reference (IDOR) detector."""

from __future__ import annotations

import re
from typing import Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from godrecon.modules.base import Finding
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_SIZE_DIFF_THRESHOLD = 0.2  # 20% difference in response size indicates IDOR


def _mutate_id(value: str) -> List[str]:
    """Return incremented and decremented variants of a numeric string."""
    try:
        num = int(value)
        return [str(num + 1), str(num - 1) if num > 1 else str(num + 2)]
    except ValueError:
        return []


class IDORDetector:
    """Detects Insecure Direct Object Reference vulnerabilities."""

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
        """Scan URL parameters for IDOR by mutating numeric IDs."""
        findings: List[Finding] = []

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        # Collect numeric params from query string and the provided params list
        numeric_params = {
            k: v[0]
            for k, v in qs.items()
            if v and re.match(r"^\d+$", v[0])
        }
        for p in params:
            if re.match(r"^\d+$", p):
                numeric_params.setdefault(p, p)

        if not numeric_params:
            return findings

        # Get baseline response
        try:
            baseline_resp = await self.http.get(url)
            if not baseline_resp:
                return findings
            baseline_body = baseline_resp.get("body", "") or ""
            baseline_status = baseline_resp.get("status_code", 200)
            baseline_size = len(baseline_body)
        except Exception as exc:
            logger.debug("IDOR baseline request error: %s", exc)
            return findings

        for param, original_value in numeric_params.items():
            for mutated in _mutate_id(original_value)[: self.max_payloads]:
                try:
                    new_qs = dict(qs)
                    new_qs[param] = [mutated]
                    new_query = urlencode({k: v[0] for k, v in new_qs.items()})
                    mutated_url = urlunparse(parsed._replace(query=new_query))

                    resp = await self.http.get(mutated_url)
                    if not resp:
                        continue
                    body = resp.get("body", "") or ""
                    status = resp.get("status_code", 0)

                    # Skip if not successful
                    if status not in (200, 201):
                        continue

                    # Compare response size
                    size = len(body)
                    if baseline_size > 0:
                        diff_ratio = abs(size - baseline_size) / baseline_size
                    else:
                        diff_ratio = 1.0 if size > 0 else 0.0

                    if diff_ratio > _SIZE_DIFF_THRESHOLD and size > 0 and body != baseline_body:
                        findings.append(Finding(
                            title=f"Potential IDOR — {url}",
                            description=(
                                f"Parameter '{param}' may expose other users' data. "
                                f"Changing value from '{original_value}' to '{mutated}' "
                                f"returned a different response ({size} vs {baseline_size} bytes)."
                            ),
                            severity="high",
                            confidence=0.6,
                            data={
                                "url": url,
                                "mutated_url": mutated_url,
                                "param": param,
                                "original_value": original_value,
                                "mutated_value": mutated,
                                "baseline_size": baseline_size,
                                "mutated_size": size,
                            },
                            tags=["idor", "p2", "high"],
                            evidence=(
                                f"Response size changed by {diff_ratio:.0%} when "
                                f"'{param}' mutated from '{original_value}' to '{mutated}'"
                            ),
                        ))
                        break
                except Exception as exc:
                    logger.debug("IDOR mutation error: %s", exc)

        return findings
