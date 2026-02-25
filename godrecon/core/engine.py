"""Main scan orchestrator for GODRECON.

The :class:`ScanEngine` discovers and loads all enabled modules, runs them
concurrently via :class:`~godrecon.core.scheduler.Scheduler`, and aggregates
the results.
"""

from __future__ import annotations

import asyncio
import importlib
import pkgutil
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from godrecon.core.config import Config, load_config
from godrecon.core.scheduler import Priority, Scheduler, Task
from godrecon.core.scope import ScopeManager
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)

# Dependency groups: modules that depend on subdomain results run after the
# subdomain pass.  Everything else can run in parallel from the start.
_SUBDOMAIN_DEPS: Set[str] = {
    "http", "http_probe", "dns", "ports", "ssl",
    "tech", "takeover", "vulns", "cloud",
    "content_discovery", "api_intel", "crawl", "network", "visual",
    "screenshots", "email_sec",
}


@dataclass
class ScanResult:
    """Aggregated results from a complete scan.

    Attributes:
        target: The primary scan target.
        started_at: Unix timestamp when the scan began.
        finished_at: Unix timestamp when the scan ended (or ``None``).
        module_results: Mapping of module name to its result data.
        errors: List of error records encountered during scanning.
        stats: Summary statistics dictionary.
    """

    target: str
    started_at: float
    finished_at: Optional[float] = None
    module_results: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """Elapsed scan time in seconds."""
        if self.finished_at is None:
            return time.time() - self.started_at
        return self.finished_at - self.started_at


class ScanEngine:
    """Orchestrates the full reconnaissance scan lifecycle.

    Discovers all enabled modules, schedules them concurrently, collects
    results, and fires real-time events for external consumers (e.g. the CLI
    progress display).

    Example::

        engine = ScanEngine(target="example.com")
        result = await engine.run()
        print(result.module_results)
    """

    def __init__(
        self,
        target: str,
        config: Optional[Config] = None,
        config_path: Optional[str] = None,
    ) -> None:
        """Initialise the scan engine.

        Args:
            target: Primary scan target (domain, IP, or CIDR).
            config: Pre-built :class:`~godrecon.core.config.Config` object. If
                    ``None`` the configuration is loaded from *config_path*.
            config_path: Optional path to a YAML configuration file.
        """
        self.target = target
        self.config: Config = config or load_config(config_path)
        self.scope = ScopeManager()
        self.scope.add_target(target)
        self._event_handlers: List[Any] = []
        # Circuit-breaker: tracks consecutive failure count per module name
        self._failure_counts: Dict[str, int] = {}
        self._circuit_open: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def on_event(self, handler: Any) -> None:
        """Register a callable to receive real-time scan events.

        Args:
            handler: An async or sync callable that accepts a ``dict`` event.
        """
        self._event_handlers.append(handler)

    async def run(self) -> ScanResult:
        """Execute the full scan and return aggregated results.

        All independent modules run in parallel.  Modules that depend on
        subdomain results are started concurrently with the subdomain module
        and simply wait for its findings to be available in a shared store
        before proceeding.

        Returns:
            :class:`ScanResult` containing data from all executed modules.
        """
        result = ScanResult(target=self.target, started_at=time.time())
        await self._emit({"event": "scan_started", "target": self.target})

        modules = self._load_modules()
        if not modules:
            logger.warning("No modules loaded for target: %s", self.target)
            result.finished_at = time.time()
            return result

        logger.info("Loaded %d modules for target: %s", len(modules), self.target)

        scheduler = Scheduler(
            concurrency=self.config.general.threads,
        )
        await scheduler.start()

        # Submit ALL modules at once for true parallel execution.
        # Subdomain module gets HIGH priority so it completes sooner and
        # downstream modules can benefit from its results.
        for module in modules:
            prio = int(Priority.HIGH) if module.name == "subdomains" else int(Priority.NORMAL)
            task = Task(
                priority=prio,
                name=module.name,
                coro_factory=lambda m=module: self._run_module(m, result),
                max_retries=self.config.general.retries,
            )
            await scheduler.submit(task)

        await scheduler.run_all()
        await scheduler.stop()

        # Optional cross-validation pass
        if self.config.general.cross_validate:
            await self._cross_validate(result)

        result.finished_at = time.time()
        result.errors = scheduler.errors

        # Build per-module health summary
        module_health: Dict[str, str] = {}
        for m in modules:
            mr = result.module_results.get(m.name)
            if m.name in self._circuit_open:
                module_health[m.name] = "circuit_open"
            elif mr is not None and getattr(mr, "error", None):
                module_health[m.name] = "error"
            elif mr is not None:
                module_health[m.name] = "ok"
            else:
                module_health[m.name] = "skipped"

        result.stats = {
            "modules_run": len(modules),
            "modules_ok": sum(1 for s in module_health.values() if s == "ok"),
            "modules_with_errors": len(scheduler.errors),
            "modules_circuit_open": len(self._circuit_open),
            "duration_seconds": round(result.duration, 2),
            "module_health": module_health,
        }

        await self._emit({"event": "scan_finished", "stats": result.stats})
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_modules(self) -> List[Any]:
        """Discover and instantiate all enabled scan modules.

        Returns:
            List of module instances ready for execution.
        """
        import godrecon.modules as modules_pkg

        enabled_modules = []
        modules_config = self.config.modules.model_dump()

        for importer, modname, ispkg in pkgutil.iter_modules(modules_pkg.__path__):
            if not ispkg:
                continue
            module_enabled = modules_config.get(modname, True)
            if not module_enabled:
                logger.debug("Module '%s' is disabled — skipping.", modname)
                continue

            try:
                pkg = importlib.import_module(f"godrecon.modules.{modname}")
                # Look for a class named after the module (CamelCase) or
                # fall back to any BaseModule subclass exported by the package.
                module_instance = self._instantiate_module(pkg, modname)
                if module_instance is not None:
                    enabled_modules.append(module_instance)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not load module '%s': %s", modname, exc)

        return enabled_modules

    @staticmethod
    def _instantiate_module(pkg: Any, modname: str) -> Optional[Any]:
        """Try to instantiate a module from its package.

        Looks for a sub-module called ``runner`` or the first exported class
        that is a subclass of :class:`~godrecon.modules.base.BaseModule`.

        Args:
            pkg: The already-imported package object.
            modname: Module directory name (e.g. ``"subdomains"``).

        Returns:
            Module instance or ``None`` if no runnable class was found.
        """
        from godrecon.modules.base import BaseModule

        # Try loading a dedicated runner sub-module first
        for sub in ("runner", "aggregator", "probe", "scanner"):
            try:
                sub_mod = importlib.import_module(f"{pkg.__name__}.{sub}")
                for attr in vars(sub_mod).values():
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseModule)
                        and attr is not BaseModule
                    ):
                        return attr()
            except ModuleNotFoundError:
                pass
            except Exception:  # noqa: BLE001
                pass

        # Fallback: scan the package's own namespace
        for attr in vars(pkg).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseModule)
                and attr is not BaseModule
            ):
                return attr()

        return None

    async def _run_module(self, module: Any, result: ScanResult) -> None:
        """Execute a single module with per-module timeout and circuit-breaker.

        Args:
            module: Module instance (must implement ``BaseModule``).
            result: The scan result object to populate.
        """
        # Circuit-breaker: skip modules that have failed too many times
        if module.name in self._circuit_open:
            logger.warning("Module '%s' circuit is open — skipping.", module.name)
            return

        await self._emit({"event": "module_started", "module": module.name})
        module_timeout = self.config.general.module_timeout
        try:
            module_result = await asyncio.wait_for(
                module.run(self.target, self.config),
                timeout=module_timeout,
            )
            result.module_results[module.name] = module_result
            # Reset failure count on success
            self._failure_counts.pop(module.name, None)
            await self._emit(
                {
                    "event": "module_finished",
                    "module": module.name,
                    "findings": len(module_result.findings) if module_result else 0,
                }
            )
        except asyncio.TimeoutError:
            logger.error(
                "Module '%s' timed out after %ds", module.name, module_timeout
            )
            self._record_failure(module.name)
            await self._emit(
                {
                    "event": "module_error",
                    "module": module.name,
                    "error": f"timed out after {module_timeout}s",
                }
            )
        except Exception as exc:  # noqa: BLE001
            tb = traceback.format_exc()
            logger.error(
                "Module '%s' failed: %s\n%s", module.name, exc, tb
            )
            self._record_failure(module.name)
            await self._emit(
                {"event": "module_error", "module": module.name, "error": str(exc)}
            )
            raise

    def _record_failure(self, module_name: str) -> None:
        """Increment failure counter and open circuit if threshold reached."""
        count = self._failure_counts.get(module_name, 0) + 1
        self._failure_counts[module_name] = count
        if count >= 3:
            self._circuit_open.add(module_name)
            logger.warning(
                "Module '%s' circuit opened after %d consecutive failures.",
                module_name,
                count,
            )

    async def _cross_validate(self, result: ScanResult) -> None:
        """Run a cross-validation pass on collected findings.

        Boosts confidence for findings confirmed by multiple modules and
        reduces confidence for unverified findings.  All validation is done
        purely on in-memory data (no additional network requests) to keep
        the pass fast and side-effect-free.

        Args:
            result: The completed scan result to validate in-place.
        """
        from godrecon.modules.base import Finding, ModuleResult

        await self._emit({"event": "cross_validation_started"})

        # Build a map: value → list of (module_name, Finding)
        value_map: Dict[str, List[Any]] = {}
        for mod_name, mr in result.module_results.items():
            if not isinstance(mr, ModuleResult):
                continue
            for finding in mr.findings:
                key = f"{finding.title}:{finding.data.get('value', finding.description)}"
                value_map.setdefault(key, []).append((mod_name, finding))

        # Boost confidence for findings confirmed by 2+ modules
        boosted = 0
        for key, entries in value_map.items():
            if len(entries) > 1:
                for _mod_name, finding in entries:
                    if finding.confidence < 1.0:
                        finding.confidence = min(1.0, finding.confidence + 0.2 * (len(entries) - 1))
                        boosted += 1

        logger.info(
            "Cross-validation complete: %d finding keys checked, %d confidence boosts applied.",
            len(value_map),
            boosted,
        )
        await self._emit(
            {
                "event": "cross_validation_finished",
                "keys_checked": len(value_map),
                "boosts_applied": boosted,
            }
        )

    async def _emit(self, event: Dict[str, Any]) -> None:
        """Fire *event* to all registered event handlers.

        Args:
            event: Dictionary describing the event.
        """
        for handler in self._event_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception:  # noqa: BLE001
                pass

