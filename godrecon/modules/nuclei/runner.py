"""Nuclei Integration module for GODRECON.

Runs the nuclei binary (if available) against the target and converts
its JSON output into GODRECON Finding objects.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Map nuclei severity labels to GODRECON severity strings
_SEVERITY_MAP: Dict[str, str] = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}

_DEFAULT_TIMEOUT = 300  # seconds


def _nuclei_available() -> Optional[str]:
    """Return path to nuclei binary, or None if not found."""
    return shutil.which("nuclei")


class NucleiModule(BaseModule):
    """Run nuclei templates against the target and import findings."""

    name = "nuclei"
    description = "Runs nuclei vulnerability scanner and imports findings into GODRECON"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "vulns"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)

        nuclei_bin = _nuclei_available()
        if not nuclei_bin:
            logger.warning(
                "nuclei binary not found — skipping nuclei scan. "
                "Install from https://github.com/projectdiscovery/nuclei"
            )
            result.raw = {"nuclei_available": False}
            return result

        logger.info("nuclei binary found at %s — running scan on %s", nuclei_bin, target)

        general = config.general
        scan_timeout = _DEFAULT_TIMEOUT

        # Build target URL
        target_url = target if target.startswith("http") else f"https://{target}"

        # Build nuclei command
        cmd = [
            nuclei_bin,
            "-u", target_url,
            "-json",           # output as JSON lines
            "-silent",         # suppress banner
            "-no-color",
            "-timeout", str(general.timeout),
        ]

        if general.proxy:
            cmd += ["-proxy", general.proxy]

        # Run nuclei in a subprocess (async via executor)
        try:
            findings = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, self._run_nuclei, cmd, scan_timeout
                ),
                timeout=scan_timeout + 10,
            )
        except asyncio.TimeoutError:
            logger.warning("nuclei scan timed out for %s", target)
            result.error = "nuclei scan timed out"
            result.raw = {"nuclei_available": True, "timed_out": True}
            return result
        except Exception as exc:
            logger.warning("nuclei scan failed for %s: %s", target, exc)
            result.error = str(exc)
            result.raw = {"nuclei_available": True, "error": str(exc)}
            return result

        for finding in findings:
            result.findings.append(finding)

        result.raw = {
            "nuclei_available": True,
            "target_url": target_url,
            "total_findings": len(findings),
        }
        logger.info("nuclei scan complete — %d findings for %s", len(findings), target)
        return result

    def _run_nuclei(self, cmd: List[str], timeout: int) -> List[Finding]:
        """Blocking nuclei execution — run in executor thread."""
        findings: List[Finding] = []
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = proc.stdout or ""
        except subprocess.TimeoutExpired:
            raise TimeoutError("nuclei subprocess timed out")
        except Exception as exc:
            raise RuntimeError(f"nuclei execution failed: {exc}") from exc

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            finding = self._nuclei_result_to_finding(data)
            if finding:
                findings.append(finding)

        return findings

    def _nuclei_result_to_finding(self, data: Dict[str, Any]) -> Optional[Finding]:
        """Convert a single nuclei JSON result into a GODRECON Finding."""
        try:
            template_id = data.get("template-id", "unknown")
            template_name = data.get("info", {}).get("name", template_id)
            severity_raw = data.get("info", {}).get("severity", "info").lower()
            severity = _SEVERITY_MAP.get(severity_raw, "info")

            matched_at = data.get("matched-at", data.get("host", ""))
            description = data.get("info", {}).get("description", "")
            tags = data.get("info", {}).get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            cve_ids = data.get("info", {}).get("classification", {}).get("cve-id", [])
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]

            cvss_score: Optional[float] = None
            cvss_raw = data.get("info", {}).get("classification", {}).get("cvss-score")
            if cvss_raw is not None:
                try:
                    cvss_score = float(cvss_raw)
                except (ValueError, TypeError):
                    pass

            # Build raw request/response if available
            raw_req = data.get("request", "")
            raw_resp = data.get("response", "")

            finding_tags = ["nuclei", severity_raw] + [str(t) for t in tags]
            if cve_ids:
                finding_tags.extend(str(c).lower() for c in cve_ids)

            return Finding(
                title=f"[nuclei] {template_name} @ {matched_at}",
                description=(
                    f"Template: {template_id}\n"
                    f"Matched at: {matched_at}\n"
                    f"Severity: {severity_raw.upper()}\n"
                    + (f"Description: {description}\n" if description else "")
                    + (f"CVEs: {', '.join(cve_ids)}\n" if cve_ids else "")
                ),
                severity=severity,
                data=data,
                tags=finding_tags,
                cvss_score=cvss_score,
                raw_request=raw_req,
                raw_response=raw_resp,
                source_module=self.name,
            )
        except Exception as exc:
            logger.debug("Failed to parse nuclei result: %s — %s", data, exc)
            return None
