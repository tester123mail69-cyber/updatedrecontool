"""Bug bounty report generator for GODRECON."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# CVSS base scores by severity
_CVSS_SCORES = {
    "critical": 9.8,
    "high": 7.5,
    "medium": 5.3,
    "low": 3.1,
    "info": 0.0,
}

# Severity to P-level mapping
_SEVERITY_TO_PLEVEL = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "info": "P5",
}


@dataclass
class BugReport:
    """A structured bug bounty report."""

    title: str
    vulnerability_type: str
    severity: str
    target: str
    description: str
    impact: str
    steps_to_reproduce: List[str] = field(default_factory=list)
    proof_of_concept: str = ""
    curl_command: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    platform: str = "hackerone"

    def to_hackerone_format(self) -> Dict[str, Any]:
        """Format as HackerOne report."""
        return {
            "title": self.title,
            "vulnerability_information": self._build_description(),
            "severity_rating": self.severity,
            "impact": self.impact,
        }

    def to_bugcrowd_format(self) -> Dict[str, Any]:
        """Format as Bugcrowd report."""
        return {
            "title": self.title,
            "description": self._build_description(),
            "severity": _SEVERITY_TO_PLEVEL.get(self.severity, "P4"),
            "target": self.target,
        }

    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            f"# {self.title}",
            "",
            f"**Severity:** {self.severity.upper()} ({_SEVERITY_TO_PLEVEL.get(self.severity, 'P4')})",
            f"**CVSS Score:** {self.cvss_score}",
            f"**Target:** {self.target}",
            f"**Date:** {self.timestamp}",
            "",
            "## Description",
            "",
            self.description,
            "",
            "## Impact",
            "",
            self.impact,
            "",
        ]

        if self.steps_to_reproduce:
            lines.extend(["## Steps to Reproduce", ""])
            for i, step in enumerate(self.steps_to_reproduce, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        if self.proof_of_concept:
            lines.extend(["## Proof of Concept", "", "```", self.proof_of_concept, "```", ""])

        if self.curl_command:
            lines.extend(["## cURL Command", "", "```bash", self.curl_command, "```", ""])

        if self.remediation:
            lines.extend(["## Remediation", "", self.remediation, ""])

        if self.references:
            lines.extend(["## References", ""])
            for ref in self.references:
                lines.append(f"- {ref}")

        return "\n".join(lines)

    def _build_description(self) -> str:
        return f"{self.description}\n\n**Steps:**\n" + "\n".join(
            f"{i}. {s}" for i, s in enumerate(self.steps_to_reproduce, 1)
        )


class BugReportGenerator:
    """Generates structured bug bounty reports from GODRECON findings."""

    def generate_from_finding(self, finding: Any, target: str, platform: str = "hackerone") -> BugReport:
        """Generate a bug report from a Finding object."""
        if hasattr(finding, "__dict__"):
            data = vars(finding)
        elif isinstance(finding, dict):
            data = finding
        else:
            data = {}

        title = data.get("title", "Vulnerability Found")
        severity = data.get("severity", "info").lower()
        description = data.get("description", "")
        evidence = data.get("evidence", "")
        finding_data = data.get("data", {})
        tags = data.get("tags", [])

        cvss = _CVSS_SCORES.get(severity, 0.0)
        curl = self._build_curl(finding_data)
        impact = self._determine_impact(severity, title, tags)
        steps = self._build_steps(title, finding_data, evidence)
        remediation = self._determine_remediation(title, tags)

        return BugReport(
            title=title,
            vulnerability_type=",".join(tags[:3]) if tags else "vulnerability",
            severity=severity,
            target=target,
            description=description,
            impact=impact,
            steps_to_reproduce=steps,
            proof_of_concept=evidence or str(finding_data),
            curl_command=curl,
            cvss_score=cvss,
            remediation=remediation,
            platform=platform,
        )

    def generate_batch(self, findings: List[Any], target: str, platform: str = "hackerone") -> List[BugReport]:
        """Generate reports for multiple findings."""
        return [self.generate_from_finding(f, target, platform) for f in findings]

    def export_json(self, reports: List[BugReport]) -> str:
        """Export reports as JSON."""
        return json.dumps(
            [
                {
                    "title": r.title,
                    "severity": r.severity,
                    "cvss_score": r.cvss_score,
                    "target": r.target,
                    "description": r.description,
                    "impact": r.impact,
                    "steps_to_reproduce": r.steps_to_reproduce,
                    "proof_of_concept": r.proof_of_concept,
                    "curl_command": r.curl_command,
                    "remediation": r.remediation,
                    "references": r.references,
                    "timestamp": r.timestamp,
                    "platform": r.platform,
                }
                for r in reports
            ],
            indent=2,
        )

    def _build_curl(self, data: Dict) -> str:
        if not isinstance(data, dict):
            return ""
        url = data.get("url", "")
        if not url:
            return ""
        method = data.get("method", "GET")
        payload = data.get("payload", "")
        param = data.get("param", "")
        if param and payload:
            return f'curl -v -X {method} "{url}?{param}={payload}"'
        return f'curl -v -X {method} "{url}"'

    def _determine_impact(self, severity: str, title: str, tags: List) -> str:
        impacts = {
            "critical": "An attacker can fully compromise the target system, potentially leading to complete data breach, remote code execution, or system takeover.",
            "high": "An attacker can gain unauthorized access to sensitive data or functionality, potentially leading to significant data exposure or privilege escalation.",
            "medium": "An attacker can exploit this vulnerability to perform unauthorized actions or access limited sensitive information.",
            "low": "This vulnerability poses a minor security risk and may provide attackers with useful information.",
            "info": "This is an informational finding that may assist attackers in reconnaissance.",
        }
        return impacts.get(severity, impacts["info"])

    def _build_steps(self, title: str, data: Dict, evidence: str) -> List[str]:
        steps = []
        if isinstance(data, dict):
            url = data.get("url", "")
            param = data.get("param", "")
            payload = data.get("payload", "")
            if url:
                steps.append(f"Navigate to: {url}")
            if param and payload:
                steps.append(f"Insert payload `{payload}` into parameter `{param}`")
                steps.append("Observe the response for vulnerability indicators")
            elif evidence:
                steps.append(f"Observe: {evidence}")
        if not steps:
            steps = [
                "Navigate to the affected endpoint",
                "Observe the vulnerability indicator in the response",
            ]
        return steps

    def _determine_remediation(self, title: str, tags: List) -> str:
        tag_str = " ".join(tags).lower()
        if "sqli" in tag_str or "sql" in tag_str:
            return "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
        elif "xss" in tag_str:
            return "Sanitize and encode all user input before rendering in HTML. Implement a Content Security Policy."
        elif "ssrf" in tag_str:
            return "Validate and whitelist allowed URLs/IP ranges. Block requests to internal network ranges."
        elif "csrf" in tag_str:
            return "Implement CSRF tokens on all state-changing requests. Verify the Origin/Referer headers."
        elif "cors" in tag_str:
            return "Restrict CORS origins to trusted domains. Avoid using wildcard (*) in Access-Control-Allow-Origin."
        else:
            return "Review and harden the affected component following security best practices."
