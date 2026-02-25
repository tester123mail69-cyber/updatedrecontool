"""Bug bounty program auto-matcher."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult

# Embedded sample bug bounty program database
_PROGRAMS: List[Dict[str, Any]] = [
    {
        "name": "Google VRP",
        "platform": "Google",
        "domains": ["google.com", "googleapis.com", "google.co", "youtube.com"],
        "max_payout": 31337,
        "scope": "All Google products",
        "url": "https://bughunters.google.com/",
    },
    {
        "name": "Microsoft MSRC",
        "platform": "HackerOne",
        "domains": ["microsoft.com", "azure.com", "live.com", "xbox.com"],
        "max_payout": 250000,
        "scope": "Microsoft products and services",
        "url": "https://www.microsoft.com/en-us/msrc/bounty",
    },
    {
        "name": "Apple Security",
        "platform": "Apple",
        "domains": ["apple.com", "icloud.com"],
        "max_payout": 1000000,
        "scope": "Apple products",
        "url": "https://security.apple.com/bounty/",
    },
    {
        "name": "HackerOne Public",
        "platform": "HackerOne",
        "domains": ["hackerone.com"],
        "max_payout": 10000,
        "scope": "HackerOne platform",
        "url": "https://hackerone.com/security",
    },
    {
        "name": "Bugcrowd",
        "platform": "Bugcrowd",
        "domains": ["bugcrowd.com"],
        "max_payout": 5000,
        "scope": "Bugcrowd platform",
        "url": "https://bugcrowd.com/bugcrowd",
    },
    {
        "name": "Facebook / Meta",
        "platform": "Facebook",
        "domains": ["facebook.com", "instagram.com", "whatsapp.com", "meta.com"],
        "max_payout": 50000,
        "scope": "Meta family of products",
        "url": "https://www.facebook.com/whitehat",
    },
    {
        "name": "GitHub",
        "platform": "HackerOne",
        "domains": ["github.com", "githubusercontent.com"],
        "max_payout": 30000,
        "scope": "GitHub products",
        "url": "https://hackerone.com/github",
    },
    {
        "name": "Shopify",
        "platform": "HackerOne",
        "domains": ["shopify.com", "shopifycloud.com", "myshopify.com"],
        "max_payout": 50000,
        "scope": "Shopify platform",
        "url": "https://hackerone.com/shopify",
    },
    {
        "name": "Twitter / X",
        "platform": "HackerOne",
        "domains": ["twitter.com", "x.com", "t.co"],
        "max_payout": 15000,
        "scope": "Twitter/X platform",
        "url": "https://hackerone.com/twitter",
    },
    {
        "name": "Dropbox",
        "platform": "HackerOne",
        "domains": ["dropbox.com", "dropboxapi.com"],
        "max_payout": 32768,
        "scope": "Dropbox products",
        "url": "https://hackerone.com/dropbox",
    },
]

_SEVERITY_PAYOUTS: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.4,
    "medium": 0.1,
    "low": 0.02,
    "info": 0.0,
}


def _match_domain(target: str, program_domains: List[str]) -> bool:
    target_lower = target.lower().lstrip("www.")
    for d in program_domains:
        if target_lower == d or target_lower.endswith(f".{d}") or d in target_lower:
            return True
    return False


class BugBountyModule(BaseModule):
    """Matches scan target to known bug bounty programs."""

    name = "bug_bounty"
    description = "Bug bounty program auto-matcher — HackerOne, Bugcrowd, Intigriti"
    version = "1.0.0"
    category = "osint"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        findings: List[Finding] = []
        matches = self._match_programs(target)

        if matches:
            for prog in matches:
                findings.append(Finding(
                    title=f"Bug Bounty Match: {prog['name']}",
                    description=(
                        f"Platform: {prog['platform']}\n"
                        f"Max payout: ${prog['max_payout']:,}\n"
                        f"Scope: {prog['scope']}\n"
                        f"URL: {prog['url']}"
                    ),
                    severity="info",
                    tags=["bug_bounty", prog["platform"].lower()],
                    data=prog,
                ))
        else:
            findings.append(Finding(
                title="Bug Bounty: No Known Program",
                description=(
                    f"No known bug bounty program matched for {target}. "
                    "Check HackerOne, Bugcrowd, and Intigriti manually."
                ),
                severity="info",
                tags=["bug_bounty"],
            ))

        return ModuleResult(module_name=self.name, target=target, findings=findings)

    def _match_programs(self, target: str) -> List[Dict[str, Any]]:
        return [p for p in _PROGRAMS if _match_domain(target, p["domains"])]

    def estimate_payout(self, program: Dict[str, Any], severity: str) -> int:
        """Estimate payout for a finding based on severity and program max."""
        multiplier = _SEVERITY_PAYOUTS.get(severity.lower(), 0.05)
        return int(program["max_payout"] * multiplier)
