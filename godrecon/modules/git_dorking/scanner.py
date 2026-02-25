"""GitHub/GitLab Dorking module for GODRECON.

Searches GitHub for leaked credentials, configs, and secrets related
to the target domain using the GitHub Code Search API.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

_GITHUB_SEARCH_URL = "https://api.github.com/search/code"

# Dork query suffixes to use for each domain
_DORK_SUFFIXES = [
    ("password", "critical"),
    ("api_key", "critical"),
    ("secret", "high"),
    ("token", "high"),
    ("credentials", "high"),
    ("config.yml", "medium"),
    (".env", "high"),
    ("private_key", "critical"),
    ("aws_secret_access_key", "critical"),
    ("database_url", "high"),
]

_RATE_LIMIT_DELAY = 2.0  # seconds between requests (unauthenticated = 10 req/min)
_AUTH_RATE_LIMIT_DELAY = 0.5  # authenticated = 30 req/min


class GitDorkingModule(BaseModule):
    """Search GitHub for leaked secrets related to the target domain."""

    name = "git_dorking"
    description = "Searches GitHub for leaked credentials and configs related to the target domain"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "osint"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)

        # Extract root domain for searching
        domain = self._extract_domain(target)

        github_token: Optional[str] = None
        if hasattr(config, "api_keys") and config.api_keys:
            github_token = getattr(config.api_keys, "github", None) or None

        delay = _AUTH_RATE_LIMIT_DELAY if github_token else _RATE_LIMIT_DELAY
        general = config.general
        timeout = general.timeout
        proxy = general.proxy
        user_agents = general.user_agents

        headers: Dict[str, str] = {
            "Accept": "application/vnd.github.v3+json",
        }
        if github_token:
            headers["Authorization"] = f"token {github_token}"
            logger.info("Git dorking with authenticated GitHub API for %s", domain)
        else:
            logger.info(
                "Git dorking without GitHub token for %s (rate limited to ~10 req/min)", domain
            )

        async with AsyncHTTPClient(
            timeout=timeout,
            user_agents=user_agents,
            proxy=proxy,
            verify_ssl=True,
            retries=1,
        ) as http:
            for suffix, severity in _DORK_SUFFIXES:
                query = f'"{domain}" {suffix}'
                findings = await self._search_github(http, query, domain, suffix, severity, headers)
                result.findings.extend(findings)
                # Respect rate limits
                await asyncio.sleep(delay)

        result.raw = {
            "domain": domain,
            "dorks_run": len(_DORK_SUFFIXES),
            "total_findings": len(result.findings),
            "authenticated": github_token is not None,
        }
        logger.info(
            "Git dorking complete for %s — %d findings", domain, len(result.findings)
        )
        return result

    async def _search_github(
        self,
        http: AsyncHTTPClient,
        query: str,
        domain: str,
        dork_type: str,
        severity: str,
        headers: Dict[str, str],
    ) -> List[Finding]:
        """Execute a single GitHub code search query and return findings."""
        findings: List[Finding] = []
        encoded_query = quote(query)
        url = f"{_GITHUB_SEARCH_URL}?q={encoded_query}&per_page=10"

        try:
            resp = await http.get(url, headers=headers, allow_redirects=True)
            if not resp:
                return findings

            status = resp.get("status", 0)
            if status == 403:
                logger.warning("GitHub API rate limit hit for query: %s", query)
                return findings
            if status == 422:
                logger.debug("GitHub query rejected (422): %s", query)
                return findings
            if status != 200:
                logger.debug("GitHub search returned %d for: %s", status, query)
                return findings

            body = resp.get("json") or {}
            items = body.get("items", [])
            total = body.get("total_count", 0)

            if not items:
                return findings

            logger.info(
                "GitHub dork '%s': %d total results (%d returned)", query, total, len(items)
            )

            for item in items:
                repo = item.get("repository", {})
                repo_name = repo.get("full_name", "unknown")
                repo_url = repo.get("html_url", "")
                file_path = item.get("path", "")
                file_url = item.get("html_url", "")

                findings.append(
                    Finding(
                        title=f"GitHub leak: '{dork_type}' related to {domain}",
                        description=(
                            f"Potential secret/credential found on GitHub.\n"
                            f"Domain: {domain}\nDork type: {dork_type}\n"
                            f"Repository: {repo_name}\nFile: {file_path}\n"
                            f"URL: {file_url}\n\n"
                            f"Total results for this query: {total}"
                        ),
                        severity=severity,
                        data={
                            "domain": domain,
                            "dork_type": dork_type,
                            "query": query,
                            "repo": repo_name,
                            "repo_url": repo_url,
                            "file_path": file_path,
                            "file_url": file_url,
                            "total_results": total,
                        },
                        tags=[
                            "git-dorking",
                            "github",
                            "leak",
                            dork_type.replace(".", "_").replace(" ", "_"),
                        ],
                        evidence=f"{repo_name}/{file_path}",
                        source_module=self.name,
                    )
                )
        except Exception as exc:
            logger.debug("GitHub search error for query '%s': %s", query, exc)

        return findings

    @staticmethod
    def _extract_domain(target: str) -> str:
        """Extract bare domain from target string."""
        target = target.strip()
        if target.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            return urlparse(target).netloc.split(":")[0]
        return target.split(":")[0].split("/")[0]
