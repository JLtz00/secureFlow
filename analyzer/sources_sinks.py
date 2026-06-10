"""Taint source, sink, and sanitizer definitions for SecureFlow."""

from __future__ import annotations

# Functions that introduce untrusted external data into the program
SOURCES: frozenset[str] = frozenset({
    "request.args.get",
    "request.form.get",
    "input",
})

# Dangerous functions where tainted data causes SQL injection
SINKS: frozenset[str] = frozenset({
    "cursor.execute",
    "engine.execute",
})

# Functions that neutralize taint — output is considered safe
SANITIZERS: frozenset[str] = frozenset({
    "escape",
    "sanitize",
})
