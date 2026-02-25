"""Business logic flaw detector."""

from __future__ import annotations

import asyncio
from typing import List

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult


class BusinessLogicModule(BaseModule):
    """Tests for business logic flaws: price manipulation, workflow bypass, race conditions."""

    name = "business_logic"
    description = "Business logic flaw detector"
    version = "1.0.0"
    category = "vuln"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        base_url = f"https://{target}" if not target.startswith("http") else target
        findings: List[Finding] = []

        tasks = [
            self._test_price_manipulation(base_url),
            self._test_quantity_tampering(base_url),
            self._test_privilege_escalation(base_url),
            self._test_workflow_bypass(base_url),
            self._test_race_condition(base_url),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        return ModuleResult(module_name=self.name, target=target, findings=findings)

    async def _test_price_manipulation(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            checkout_paths = ["/checkout", "/api/cart/checkout", "/api/orders",
                              "/api/v1/checkout", "/cart/pay"]
            async with aiohttp.ClientSession() as session:
                for path in checkout_paths:
                    url = f"{base_url}{path}"
                    for bad_price in [-1, 0, 0.001]:
                        try:
                            async with session.post(
                                url,
                                json={"price": bad_price, "amount": bad_price, "total": bad_price},
                                timeout=aiohttp.ClientTimeout(total=5),
                                allow_redirects=False,
                            ) as resp:
                                if resp.status in (200, 201):
                                    findings.append(Finding(
                                        title=f"Price Manipulation Possible: {path}",
                                        description=(
                                            f"Endpoint {url} accepted price={bad_price}. "
                                            "Verify server-side price validation."
                                        ),
                                        severity="high",
                                        tags=["business_logic", "price_manipulation"],
                                        data={"url": url, "test_price": bad_price},
                                    ))
                        except Exception:  # noqa: BLE001
                            pass
        except ImportError:
            pass
        return findings

    async def _test_quantity_tampering(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            paths = ["/api/cart", "/api/cart/update", "/api/orders/items"]
            async with aiohttp.ClientSession() as session:
                for path in paths:
                    url = f"{base_url}{path}"
                    try:
                        async with session.post(
                            url,
                            json={"quantity": -1, "qty": -1},
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=False,
                        ) as resp:
                            if resp.status in (200, 201):
                                findings.append(Finding(
                                    title=f"Quantity Tampering Possible: {path}",
                                    description=(
                                        f"Endpoint {url} accepted negative quantity. "
                                        "May allow credit accumulation."
                                    ),
                                    severity="high",
                                    tags=["business_logic", "quantity_tampering"],
                                    data={"url": url},
                                ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _test_privilege_escalation(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            admin_paths = [
                "/api/admin", "/api/v1/admin", "/admin/api",
                "/api/users/promote", "/api/user/role",
            ]
            async with aiohttp.ClientSession() as session:
                for path in admin_paths:
                    url = f"{base_url}{path}"
                    try:
                        async with session.post(
                            url,
                            json={"role": "admin", "is_admin": True, "privilege": "admin"},
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=False,
                        ) as resp:
                            if resp.status in (200, 201, 204):
                                findings.append(Finding(
                                    title=f"Privilege Escalation Endpoint: {path}",
                                    description=(
                                        f"Endpoint {url} accepts role change without apparent authorization check."
                                    ),
                                    severity="critical",
                                    tags=["business_logic", "privilege_escalation"],
                                    data={"url": url, "status": resp.status},
                                ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _test_workflow_bypass(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            # Test for step skipping in multi-step workflows
            end_paths = [
                "/api/orders/complete", "/checkout/complete",
                "/api/payment/confirm", "/api/v1/payment/success",
            ]
            async with aiohttp.ClientSession() as session:
                for path in end_paths:
                    url = f"{base_url}{path}"
                    try:
                        async with session.post(
                            url,
                            json={"order_id": "test-123", "status": "complete"},
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=False,
                        ) as resp:
                            if resp.status in (200, 201, 302):
                                findings.append(Finding(
                                    title=f"Workflow Bypass Candidate: {path}",
                                    description=(
                                        f"Endpoint {url} responded to direct step-completion request. "
                                        "Test for full workflow bypass."
                                    ),
                                    severity="high",
                                    tags=["business_logic", "workflow_bypass"],
                                    data={"url": url, "status": resp.status},
                                ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings

    async def _test_race_condition(self, base_url: str) -> List[Finding]:
        findings = []
        try:
            import aiohttp
            redeem_paths = [
                "/api/coupon/redeem", "/api/voucher/use",
                "/api/promo/apply", "/api/referral/redeem",
            ]
            async with aiohttp.ClientSession() as session:
                for path in redeem_paths:
                    url = f"{base_url}{path}"
                    # Send concurrent requests to test race condition
                    tasks = []
                    for _ in range(3):
                        tasks.append(session.post(
                            url,
                            json={"code": "TESTRACE100", "coupon": "TESTRACE100"},
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=False,
                        ))
                    try:
                        responses = await asyncio.gather(*[t.__aenter__() for t in tasks], return_exceptions=True)
                        success_count = sum(
                            1 for r in responses
                            if hasattr(r, "status") and r.status in (200, 201)
                        )
                        for t in tasks:
                            try:
                                await t.__aexit__(None, None, None)
                            except Exception:  # noqa: BLE001
                                pass
                        if success_count > 1:
                            findings.append(Finding(
                                title=f"Race Condition Detected: {path}",
                                description=(
                                    f"Concurrent requests to {url} all succeeded — race condition possible."
                                ),
                                severity="high",
                                tags=["business_logic", "race_condition"],
                                data={"url": url, "success_count": success_count},
                            ))
                    except Exception:  # noqa: BLE001
                        pass
        except ImportError:
            pass
        return findings
