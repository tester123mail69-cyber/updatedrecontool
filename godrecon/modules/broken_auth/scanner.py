"""Broken authentication deep scanner."""

from __future__ import annotations

import asyncio
import base64
import json
import re
from typing import List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult


def _decode_jwt(token: str) -> dict:
    """Decode a JWT payload without verification."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:  # noqa: BLE001
        return {}


class BrokenAuthModule(BaseModule):
    """Tests for broken authentication vulnerabilities."""

    name = "broken_auth"
    description = "Broken authentication deep scanner"
    version = "1.0.0"
    category = "auth"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        cfg = config.broken_auth
        base_url = f"https://{target}" if not target.startswith("http") else target
        findings: List[Finding] = []

        tasks = []
        if cfg.test_password_reset:
            tasks.append(self._test_password_reset_poisoning(base_url))
        if cfg.test_2fa_bypass:
            tasks.append(self._test_2fa_bypass(base_url))
        if cfg.test_oauth:
            tasks.append(self._test_oauth_misconfig(base_url))
        if cfg.test_jwt:
            tasks.append(self._test_jwt_confusion(base_url))
        tasks.append(self._test_username_enumeration(base_url))
        tasks.append(self._test_session_fixation(base_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return ModuleResult(module_name=self.name, target=target, findings=findings)

    async def _test_password_reset_poisoning(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            reset_paths = ["/forgot-password", "/reset-password", "/account/password/reset",
                           "/api/auth/forgot", "/api/v1/auth/password/reset"]
            async with aiohttp.ClientSession() as session:
                for path in reset_paths:
                    url = f"{base_url}{path}"
                    try:
                        async with session.post(
                            url,
                            headers={"Host": "evil.com", "X-Forwarded-Host": "evil.com"},
                            json={"email": "test@example.com"},
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=False,
                        ) as resp:
                            if resp.status in (200, 400, 422):
                                findings.append(Finding(
                                    title="Password Reset Endpoint Found",
                                    description=(
                                        f"Password reset endpoint at {url} — test for "
                                        "Host header poisoning (X-Forwarded-Host: evil.com)"
                                    ),
                                    severity="medium",
                                    tags=["broken_auth", "password_reset"],
                                    data={"url": url, "status": resp.status},
                                ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _test_2fa_bypass(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            paths = ["/api/auth/verify-otp", "/api/2fa/verify", "/login/otp", "/verify"]
            async with aiohttp.ClientSession() as session:
                for path in paths:
                    url = f"{base_url}{path}"
                    for payload in [{"otp": "000000"}, {"code": "000000"}, {"token": "000000"}]:
                        try:
                            async with session.post(
                                url, json=payload,
                                timeout=aiohttp.ClientTimeout(total=5),
                                allow_redirects=False,
                            ) as resp:
                                if resp.status in (200, 302):
                                    findings.append(Finding(
                                        title=f"Potential 2FA Bypass: {url}",
                                        description="2FA endpoint responds to OTP 000000 — verify bypass not possible.",
                                        severity="high",
                                        tags=["broken_auth", "2fa_bypass"],
                                        data={"url": url, "status": resp.status},
                                    ))
                        except Exception:  # noqa: BLE001
                            pass
        except ImportError:
            pass
        return findings

    async def _test_oauth_misconfig(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            oauth_paths = [
                "/oauth/authorize",
                "/api/oauth/callback",
                "/.well-known/openid-configuration",
                "/oauth2/authorize",
            ]
            async with aiohttp.ClientSession() as session:
                for path in oauth_paths:
                    url = f"{base_url}{path}"
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp:
                            if resp.status in (200, 302, 400):
                                # Check for open redirect in redirect_uri
                                if "redirect_uri" in str(resp.headers) or resp.status == 200:
                                    findings.append(Finding(
                                        title=f"OAuth Endpoint Found: {path}",
                                        description=(
                                            f"OAuth endpoint at {url} — test for: "
                                            "open redirect_uri, implicit flow, token leakage."
                                        ),
                                        severity="medium",
                                        tags=["broken_auth", "oauth"],
                                        data={"url": url, "status": resp.status},
                                    ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _test_jwt_confusion(self, base_url: str) -> List[Finding]:
        findings = []
        # Craft alg:none JWT
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"admin","role":"admin"}').rstrip(b"=").decode()
        none_jwt = f"{header}.{payload}."
        findings.append(Finding(
            title="JWT Algorithm Confusion Test",
            description=(
                f"Test target with alg:none JWT: {none_jwt[:80]}... "
                "If accepted, allows authentication bypass."
            ),
            severity="info",
            tags=["broken_auth", "jwt"],
            data={"poc_token": none_jwt},
        ))
        return findings

    async def _test_username_enumeration(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            login_paths = ["/login", "/api/login", "/api/auth/login", "/api/v1/login"]
            async with aiohttp.ClientSession() as session:
                for path in login_paths:
                    url = f"{base_url}{path}"
                    responses = {}
                    for username, password in [
                        ("admin@example.com", "wrongpassword123!"),
                        ("nonexistentuser99999@example.com", "wrongpassword123!"),
                    ]:
                        try:
                            async with session.post(
                                url,
                                json={"username": username, "email": username, "password": password},
                                timeout=aiohttp.ClientTimeout(total=5),
                                allow_redirects=False,
                            ) as resp:
                                body = await resp.text()
                                responses[username] = {"status": resp.status, "len": len(body)}
                        except Exception:  # noqa: BLE001
                            pass
                    if len(responses) == 2:
                        statuses = [v["status"] for v in responses.values()]
                        lens = [v["len"] for v in responses.values()]
                        if statuses[0] != statuses[1] or abs(lens[0] - lens[1]) > 20:
                            findings.append(Finding(
                                title=f"Username Enumeration Possible: {path}",
                                description=(
                                    f"Login endpoint {url} returns different responses "
                                    "for valid vs invalid usernames."
                                ),
                                severity="medium",
                                tags=["broken_auth", "username_enumeration"],
                                data={"url": url, "responses": responses},
                            ))
        except ImportError:
            pass
        return findings

    async def _test_session_fixation(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        base_url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        pre_cookies = dict(resp.cookies)
                        if pre_cookies:
                            # After "login", check if session ID changes
                            findings.append(Finding(
                                title="Session Fixation: Pre-auth Cookies Set",
                                description=(
                                    f"Server sets cookies before authentication: "
                                    f"{list(pre_cookies.keys())} — verify session ID rotates on login."
                                ),
                                severity="low",
                                tags=["broken_auth", "session_fixation"],
                                data={"cookies": list(pre_cookies.keys())},
                            ))
                except Exception:  # noqa: BLE001
                    pass
        except ImportError:
            pass
        return findings
