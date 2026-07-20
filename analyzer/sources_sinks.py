"""Taint source, sink, and sanitizer definitions for SecureFlow."""

from __future__ import annotations

from analyzer.framework_profiles import BASE_PROFILE

# Default profile kept for backwards-compatible imports.
SOURCES: frozenset[str] = BASE_PROFILE.sources
SINKS: frozenset[str] = BASE_PROFILE.sinks
SANITIZERS: frozenset[str] = BASE_PROFILE.sanitizers
