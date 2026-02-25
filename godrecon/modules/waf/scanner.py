"""WAF Detection and Bypass module for GODRECON.

Detects Web Application Firewalls by analysing response headers, body
signatures, and cookies. Returns bypass suggestions when a WAF is found.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# WAF attack probe — triggers most WAFs without being truly malicious
_ATTACK_PROBE = "/?id=1'%20OR%20'1'='1&<script>alert(1)</script>"

# WAF signatures: (waf_name, header_checks, body_checks, cookie_checks)
# header_checks: list of (header_name, value_pattern)
# body_checks:   list of regex patterns
# cookie_checks: list of regex patterns on Set-Cookie
_WAF_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Cloudflare",
        "headers": [("cf-ray", r".+"), ("server", r"cloudflare")],
        "body": [r"cloudflare", r"Attention Required!", r"cf-wrapper"],
        "cookies": [r"__cfduid", r"__cf_bm"],
        "bypasses": [
            "Use Cloudflare IP ranges bypass via origin IP discovery",
            "Try adding X-Forwarded-For: 127.0.0.1 header",
            "Attempt direct IP access to bypass CDN",
        ],
    },
    {
        "name": "AWS WAF",
        "headers": [("x-amzn-requestid", r".+"), ("x-amzn-trace-id", r".+")],
        "body": [r"AWS WAF", r"Request blocked"],
        "cookies": [],
        "bypasses": [
            "Try encoding payloads with double URL encoding",
            "Use HTTP/2 smuggling techniques",
            "Attempt JSON body injection to bypass rule parsing",
        ],
    },
    {
        "name": "Akamai",
        "headers": [("x-check-cacheable", r".+"), ("server", r"AkamaiGHost")],
        "body": [r"akamai", r"Reference #[0-9]+\.[0-9a-f]+\.[0-9]+"],
        "cookies": [r"ak_bmsc", r"bm_sz"],
        "bypasses": [
            "Try chunked transfer encoding to bypass inspection",
            "Use uncommon HTTP methods",
            "Attempt header injection via HTTP/1.0",
        ],
    },
    {
        "name": "Sucuri",
        "headers": [("x-sucuri-id", r".+"), ("x-sucuri-cache", r".+")],
        "body": [r"Sucuri WebSite Firewall", r"sucuri\.net"],
        "cookies": [],
        "bypasses": [
            "Try accessing origin server directly",
            "Use HTTP parameter pollution",
            "Attempt case variation in payloads",
        ],
    },
    {
        "name": "Imperva (Incapsula)",
        "headers": [("x-iinfo", r".+")],
        "body": [r"incapsula", r"Incapsula incident", r"/_Incapsula_Resource"],
        "cookies": [r"incap_ses", r"visid_incap"],
        "bypasses": [
            "Try Unicode normalization bypass",
            "Use comment-based SQL injection variants",
            "Attempt multipart/form-data with payload in filename",
        ],
    },
    {
        "name": "ModSecurity",
        "headers": [("server", r"(?i)mod_security"), ("x-waf-status", r".+")],
        "body": [r"Mod_Security", r"NOYB", r"ModSecurity Action", r"406 Not Acceptable"],
        "cookies": [],
        "bypasses": [
            "Try HPP (HTTP Parameter Pollution)",
            "Use whitespace variations in SQL keywords",
            "Attempt chunked encoding to bypass body inspection",
        ],
    },
    {
        "name": "F5 BIG-IP ASM",
        "headers": [("x-cnection", r".+"), ("server", r"BigIP")],
        "body": [r"The requested URL was rejected", r"F5 Networks"],
        "cookies": [r"BIGipServer", r"F5_"],
        "bypasses": [
            "Try path normalization attacks",
            "Use overlong UTF-8 encoding",
            "Attempt null byte injection",
        ],
    },
]


def _check_waf_signatures(
    headers: Dict[str, str],
    body: str,
    cookies: str,
) -> Optional[Dict[str, Any]]:
    """Check response against all WAF signatures; return first match or None."""
    body_lower = body.lower()
    for waf in _WAF_SIGNATURES:
        matched = False
        # Header checks (any match counts)
        for hdr_name, hdr_pattern in waf.get("headers", []):
            val = headers.get(hdr_name.lower(), "")
            if val and re.search(hdr_pattern, val, re.IGNORECASE):
                matched = True
                break
        # Body checks
        if not matched:
            for body_pattern in waf.get("body", []):
                if re.search(body_pattern, body_lower, re.IGNORECASE):
                    matched = True
                    break
        # Cookie checks
        if not matched:
            for cookie_pattern in waf.get("cookies", []):
                if re.search(cookie_pattern, cookies, re.IGNORECASE):
                    matched = True
                    break
        if matched:
            return waf
    return None


class WAFModule(BaseModule):
    """Detect WAF presence and provide bypass suggestions."""

    name = "waf"
    description = "Detects WAF by response headers, body signatures, and cookie patterns"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "detection"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)

        general = config.general
        timeout = general.timeout
        proxy = general.proxy
        user_agents = general.user_agents

        base_url = f"https://{target}" if not target.startswith("http") else target

        async with AsyncHTTPClient(
            timeout=timeout,
            user_agents=user_agents,
            proxy=proxy,
            verify_ssl=False,
            retries=1,
        ) as http:
            # Normal request baseline
            normal_resp = await self._fetch(http, base_url)
            # Attack probe request
            attack_url = base_url.rstrip("/") + _ATTACK_PROBE
            attack_resp = await self._fetch(http, attack_url)

        detected_waf: Optional[Dict[str, Any]] = None

        # Check attack response first (more likely to trigger WAF)
        for resp in (attack_resp, normal_resp):
            if resp is None:
                continue
            headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
            body = resp.get("body", "") or ""
            cookies = headers.get("set-cookie", "")
            waf = _check_waf_signatures(headers, body, cookies)
            if waf:
                detected_waf = waf
                break

        # Also check generic WAF headers
        generic_waf_headers = [
            "x-waf-status", "x-waf-event-info", "x-firewall-protection",
            "x-cdn", "x-sucuri-id", "x-iinfo",
        ]
        if not detected_waf and normal_resp:
            hdrs = {k.lower(): v for k, v in (normal_resp.get("headers") or {}).items()}
            for h in generic_waf_headers:
                if h in hdrs:
                    detected_waf = {
                        "name": "Unknown WAF",
                        "bypasses": ["Manual analysis required — WAF header detected"],
                    }
                    break

        if detected_waf:
            waf_name = detected_waf["name"]
            bypasses = detected_waf.get("bypasses", [])
            result.findings.append(
                Finding(
                    title=f"WAF Detected: {waf_name}",
                    description=(
                        f"A Web Application Firewall ({waf_name}) was detected on {target}.\n\n"
                        f"Bypass suggestions:\n"
                        + "\n".join(f"  • {b}" for b in bypasses)
                    ),
                    severity="info",
                    data={
                        "waf": waf_name,
                        "target": target,
                        "bypasses": bypasses,
                    },
                    tags=["waf", "detection", waf_name.lower().replace(" ", "-")],
                    source_module=self.name,
                )
            )
            result.raw["waf_detected"] = waf_name
        else:
            result.raw["waf_detected"] = None

        logger.info(
            "WAF detection complete for %s — WAF: %s",
            target,
            detected_waf["name"] if detected_waf else "None",
        )
        return result

    @staticmethod
    async def _fetch(
        http: AsyncHTTPClient, url: str
    ) -> Optional[Dict[str, Any]]:
        try:
            return await http.get(url, allow_redirects=True)
        except Exception as exc:
            logger.debug("WAF probe fetch failed for %s: %s", url, exc)
            return None
