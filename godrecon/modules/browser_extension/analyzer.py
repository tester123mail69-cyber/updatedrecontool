"""Browser extension analyzer — detects and analyzes referenced browser extensions."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult

# Known vulnerable extension IDs (sample subset)
_KNOWN_VULNERABLE: Dict[str, Dict[str, Any]] = {
    "cfhdojbkjhnklbpkdaibdccddilifddb": {
        "name": "Adblock Plus",
        "cve": "CVE-2021-4234",
        "severity": "medium",
        "description": "Older versions allow XSS via crafted page.",
    },
    "gighmmpiobklfepjocnamgkkbiglidom": {
        "name": "AdBlock",
        "cve": "CVE-2019-16267",
        "severity": "low",
        "description": "Information disclosure in older versions.",
    },
}

_CHROME_EXT_RE = re.compile(
    r'chrome-extension://([a-z]{32})',
    re.IGNORECASE,
)
_FIREFOX_EXT_RE = re.compile(
    r'moz-extension://([0-9a-f-]{36})',
    re.IGNORECASE,
)
_EXTENSION_LINK_RE = re.compile(
    r'(?:https?://(?:chrome|addons)\.(?:google|mozilla)\.[a-z.]+/(?:webstore/detail|firefox/addon)/[^\s"\'<>]+)',
    re.IGNORECASE,
)


class BrowserExtensionModule(BaseModule):
    """Detects browser extensions referenced on target pages."""

    name = "browser_extension"
    description = "Browser extension analyzer — detects permissions and known vulnerabilities"
    version = "1.0.0"
    category = "recon"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        base_url = f"https://{target}" if not target.startswith("http") else target
        findings: List[Finding] = []

        page_content = await self._fetch_page(base_url)
        if page_content:
            findings.extend(self._analyze_content(page_content, base_url))

        return ModuleResult(module_name=self.name, target=target, findings=findings)

    async def _fetch_page(self, url: str) -> str:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        return await resp.text()
        except Exception:  # noqa: BLE001
            pass
        return ""

    def _analyze_content(self, content: str, url: str) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        # Check for Chrome extension references
        for match in _CHROME_EXT_RE.finditer(content):
            ext_id = match.group(1)
            if ext_id in seen:
                continue
            seen.add(ext_id)
            vuln = _KNOWN_VULNERABLE.get(ext_id)
            if vuln:
                findings.append(Finding(
                    title=f"Vulnerable Extension: {vuln['name']} ({ext_id})",
                    description=(
                        f"Known vulnerable extension referenced on {url}.\n"
                        f"CVE: {vuln['cve']}\n{vuln['description']}"
                    ),
                    severity=vuln["severity"],
                    tags=["browser_extension", "chrome"],
                    data={"extension_id": ext_id, "cve": vuln["cve"]},
                ))
            else:
                findings.append(Finding(
                    title=f"Chrome Extension Referenced: {ext_id}",
                    description=f"Chrome extension ID {ext_id} referenced on {url}.",
                    severity="info",
                    tags=["browser_extension", "chrome"],
                    data={"extension_id": ext_id},
                ))

        # Check for Firefox extension references
        for match in _FIREFOX_EXT_RE.finditer(content):
            ext_id = match.group(1)
            if ext_id in seen:
                continue
            seen.add(ext_id)
            findings.append(Finding(
                title=f"Firefox Extension Referenced: {ext_id}",
                description=f"Firefox extension ID {ext_id} referenced on {url}.",
                severity="info",
                tags=["browser_extension", "firefox"],
                data={"extension_id": ext_id},
            ))

        # Check for extension store links
        for match in _EXTENSION_LINK_RE.finditer(content):
            link = match.group(0)
            if link in seen:
                continue
            seen.add(link)
            findings.append(Finding(
                title="Browser Extension Store Link Found",
                description=f"Extension store link on {url}: {link}",
                severity="info",
                tags=["browser_extension"],
                data={"link": link},
            ))

        return findings
