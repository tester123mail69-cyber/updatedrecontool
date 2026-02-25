"""Vulnerability chaining module — detects exploit chains from combined findings."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult

# Chain rules: (tag_a, tag_b, chain_title, impact, combined_severity)
_CHAIN_RULES: List[Tuple[str, str, str, str, str]] = [
    (
        "open_redirect",
        "oauth",
        "Account Takeover via Open Redirect + OAuth",
        "Attacker can steal OAuth tokens and take over accounts.",
        "critical",
    ),
    (
        "ssrf",
        "cloud",
        "RCE via SSRF + Cloud Metadata Access",
        "SSRF reaching cloud metadata endpoint may yield credentials enabling RCE.",
        "critical",
    ),
    (
        "xss",
        "csrf",
        "Privilege Escalation via XSS + CSRF",
        "XSS can be used to perform CSRF attacks with victim session.",
        "high",
    ),
    (
        "idor",
        "privilege_escalation",
        "Full Account Compromise via IDOR + Privilege Escalation",
        "IDOR combined with privilege escalation allows full account takeover.",
        "critical",
    ),
    (
        "sqli",
        "auth_bypass",
        "Authentication Bypass via SQLi",
        "SQL injection can be used to bypass authentication entirely.",
        "critical",
    ),
    (
        "path_traversal",
        "file_include",
        "Remote Code Execution via Path Traversal + File Include",
        "Path traversal feeding into a file include can result in RCE.",
        "critical",
    ),
    (
        "xxe",
        "ssrf",
        "Internal Network Access via XXE + SSRF",
        "XXE can be combined with SSRF to pivot to internal services.",
        "high",
    ),
]


def _tags_of(findings: List[Finding]) -> set:
    tags = set()
    for f in findings:
        tags.update(t.lower() for t in f.tags)
        tags.update(f.title.lower().split())
    return tags


class VulnChainingModule(BaseModule):
    """Detects exploit chains from combinations of existing findings."""

    name = "vuln_chaining"
    description = "Auto vulnerability chaining — detects multi-step exploit paths"
    version = "1.0.0"
    category = "vuln"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        # This module is typically called with extra context; standalone run returns info
        findings: List[Finding] = []
        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=findings,
            raw={"info": "Call analyze_findings() with results from other modules"},
        )

    def analyze_findings(self, all_findings: List[Finding]) -> List[Finding]:
        """Detect exploit chains from a list of findings.

        Args:
            all_findings: Combined findings from all scan modules.

        Returns:
            New chain findings.
        """
        present_tags = _tags_of(all_findings)
        chains: List[Finding] = []

        for tag_a, tag_b, title, impact, severity in _CHAIN_RULES:
            if any(tag_a in t for t in present_tags) and any(tag_b in t for t in present_tags):
                chains.append(Finding(
                    title=title,
                    description=(
                        f"Chain detected: [{tag_a}] + [{tag_b}]\n{impact}"
                    ),
                    severity=severity,
                    impact=impact,
                    tags=["vuln_chain", tag_a, tag_b],
                    data={"chain_components": [tag_a, tag_b]},
                ))

        return chains
