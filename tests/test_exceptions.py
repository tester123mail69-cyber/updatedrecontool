"""Tests for godrecon.core.exceptions."""

from __future__ import annotations

import pytest

from godrecon.core.exceptions import (
    ConfigError,
    GodReconError,
    ModuleError,
    SchedulerError,
    ScopeError,
)


def test_godrecon_error_is_exception():
    assert issubclass(GodReconError, Exception)


def test_module_error_inherits_godrecon_error():
    assert issubclass(ModuleError, GodReconError)


def test_config_error_inherits_godrecon_error():
    assert issubclass(ConfigError, GodReconError)


def test_scope_error_inherits_godrecon_error():
    assert issubclass(ScopeError, GodReconError)


def test_scheduler_error_inherits_godrecon_error():
    assert issubclass(SchedulerError, GodReconError)


def test_all_subclasses_catchable_as_godrecon_error():
    for cls in (ModuleError, ConfigError, ScopeError, SchedulerError):
        with pytest.raises(GodReconError):
            raise cls("test message")


def test_exception_message_preserved():
    with pytest.raises(ModuleError, match="dns lookup failed"):
        raise ModuleError("dns lookup failed")
