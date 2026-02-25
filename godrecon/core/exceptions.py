"""Custom exception hierarchy for GodRecon.

Importing from this module lets callers catch specific error categories
instead of relying on bare ``except Exception: pass`` blocks.
"""

from __future__ import annotations


class GodReconError(Exception):
    """Base exception for all GodRecon errors.

    Raise (or subclass) this whenever an error originates inside the
    GodRecon package so callers can distinguish tool errors from
    unexpected third-party or built-in exceptions.
    """


class ModuleError(GodReconError):
    """Raised when a recon module fails during execution.

    Use this to signal that a specific module could not complete its
    work, e.g. a network call failed or an external tool was missing.
    """


class ConfigError(GodReconError):
    """Raised when configuration is missing, invalid, or inconsistent.

    Use this when loading or validating ``config.yaml`` or when a
    required configuration key is absent.
    """


class ScopeError(GodReconError):
    """Raised when a target falls outside the defined scan scope.

    Use this when a target domain, IP, or URL is rejected by the scope
    filter before scanning begins.
    """


class SchedulerError(GodReconError):
    """Raised when the scan scheduler encounters an unrecoverable problem.

    Use this for failures in job queuing, concurrency limits, or
    scheduled-task management.
    """
