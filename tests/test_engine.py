"""Tests for godrecon.core.engine."""

from __future__ import annotations

import asyncio
import pkgutil
from unittest.mock import MagicMock, patch

import pytest

import godrecon.modules as modules_pkg
from godrecon.core.config import Config
from godrecon.core.engine import ScanEngine, ScanResult
from godrecon.modules.base import BaseModule, Finding, ModuleResult


def test_engine_initialises_with_target():
    engine = ScanEngine(target="example.com", config=Config())
    assert engine.target == "example.com"
    assert engine.scope.in_scope("example.com")


def test_engine_initialises_with_config():
    cfg = Config()
    engine = ScanEngine(target="example.com", config=cfg)
    assert engine.config is cfg


def test_scan_result_duration():
    import time

    result = ScanResult(target="example.com", started_at=time.time() - 5)
    assert result.duration >= 5
    result.finished_at = result.started_at + 3
    assert abs(result.duration - 3) < 0.01


def test_module_discovery_finds_packages():
    """Engine discovers all sub-packages under godrecon/modules/."""
    discovered = [
        name
        for _, name, ispkg in pkgutil.iter_modules(modules_pkg.__path__)
        if ispkg
    ]
    expected = [
        "api_intel", "cloud", "content_discovery", "crawl", "dns",
        "email_sec", "http", "network", "osint", "ports",
        "screenshots", "ssl", "subdomains", "takeover", "tech", "visual", "vulns",
    ]
    for mod in expected:
        assert mod in discovered, f"Module '{mod}' not found in modules package"


def test_engine_on_event_registers_handler():
    engine = ScanEngine(target="example.com", config=Config())
    handler = MagicMock()
    engine.on_event(handler)
    assert handler in engine._event_handlers


@pytest.mark.asyncio
async def test_engine_run_no_modules_loaded():
    """Engine completes gracefully when no modules can be loaded."""
    engine = ScanEngine(target="example.com", config=Config())
    with patch.object(engine, "_load_modules", return_value=[]):
        result = await engine.run()
    assert result.target == "example.com"
    assert result.finished_at is not None
    assert result.module_results == {}


# ---------------------------------------------------------------------------
# New tests for parallel execution and robustness improvements
# ---------------------------------------------------------------------------

class _FastModule(BaseModule):
    name = "fast_mod"
    description = "Fast test module"
    category = "test"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=[Finding(title="fast finding", confidence=0.9)],
        )


class _SlowTimeoutModule(BaseModule):
    name = "slow_mod"
    description = "Slow module that times out"
    category = "test"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        await asyncio.sleep(999)  # will be cancelled by timeout
        return ModuleResult(module_name=self.name, target=target)


@pytest.mark.asyncio
async def test_engine_parallel_execution_runs_all_modules():
    """All modules should be submitted and run in the single parallel pass."""
    cfg = Config()
    engine = ScanEngine(target="example.com", config=cfg)

    modules = [_FastModule(), _FastModule()]
    modules[0].name = "mod_a"
    modules[1].name = "mod_b"

    with patch.object(engine, "_load_modules", return_value=modules):
        result = await engine.run()

    assert "mod_a" in result.module_results
    assert "mod_b" in result.module_results
    assert result.stats["modules_run"] == 2


@pytest.mark.asyncio
async def test_engine_module_timeout_does_not_crash_scan():
    """A module that times out must not crash the entire scan."""
    cfg = Config()
    cfg.general.module_timeout = 1  # 1-second timeout
    engine = ScanEngine(target="example.com", config=cfg)

    fast = _FastModule()
    slow = _SlowTimeoutModule()

    with patch.object(engine, "_load_modules", return_value=[fast, slow]):
        result = await engine.run()

    # Fast module should complete; slow module should time out gracefully
    assert "fast_mod" in result.module_results
    assert result.finished_at is not None


@pytest.mark.asyncio
async def test_engine_circuit_breaker_opens_after_three_failures():
    """Circuit breaker should open after 3 consecutive failures."""
    engine = ScanEngine(target="example.com", config=Config())
    for _ in range(3):
        engine._record_failure("test_module")
    assert "test_module" in engine._circuit_open


@pytest.mark.asyncio
async def test_engine_circuit_breaker_skips_open_circuit():
    """A module with an open circuit should be skipped."""
    engine = ScanEngine(target="example.com", config=Config())
    engine._circuit_open.add("fast_mod")

    mod = _FastModule()
    result = ScanResult(target="example.com", started_at=0)
    await engine._run_module(mod, result)

    # Module should not have run
    assert "fast_mod" not in result.module_results


@pytest.mark.asyncio
async def test_engine_stats_include_module_health():
    """Scan stats should include per-module health status."""
    cfg = Config()
    engine = ScanEngine(target="example.com", config=cfg)

    with patch.object(engine, "_load_modules", return_value=[_FastModule()]):
        result = await engine.run()

    assert "module_health" in result.stats
    assert result.stats["module_health"].get("fast_mod") == "ok"


@pytest.mark.asyncio
async def test_engine_cross_validation_boosts_confidence():
    """Cross-validation should boost confidence for multi-module confirmed findings."""
    cfg = Config()
    cfg.general.cross_validate = True
    engine = ScanEngine(target="example.com", config=cfg)

    # Two findings with the same title+value from different modules
    f1 = Finding(title="dup", confidence=0.5, data={"value": "x"})
    f2 = Finding(title="dup", confidence=0.5, data={"value": "x"})
    mr1 = ModuleResult(module_name="mod1", target="example.com", findings=[f1])
    mr2 = ModuleResult(module_name="mod2", target="example.com", findings=[f2])

    result = ScanResult(
        target="example.com",
        started_at=0,
        module_results={"mod1": mr1, "mod2": mr2},
    )
    await engine._cross_validate(result)

    # Both findings should have boosted confidence
    assert f1.confidence > 0.5
    assert f2.confidence > 0.5

