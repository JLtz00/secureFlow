"""Small dependency-free test runner for SecureFlow's pytest-style tests."""

from __future__ import annotations

import importlib
from pathlib import Path


def main() -> int:
    total = 0
    failures: list[tuple[str, str, str, str]] = []

    for path in sorted(Path("tests").glob("test_*.py")):
        module = importlib.import_module(f"tests.{path.stem}")
        names = sorted(name for name in dir(module) if name.startswith("test_"))
        for name in names:
            total += 1
            try:
                getattr(module, name)()
            except Exception as exc:  # pragma: no cover - only exercised on failure
                failures.append((path.name, name, type(exc).__name__, str(exc)))

    print(f"tests={total} failed={len(failures)}")
    for filename, name, error_type, message in failures:
        print(f"- {filename}::{name}: {error_type}: {message}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
