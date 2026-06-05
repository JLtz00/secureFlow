"""Symbol model for SecureFlow semantic analysis."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Symbol:
    name: str
    kind: str
    type_name: str = "unknown"
    is_tainted: bool = False
    scope_name: str = "global"
    line: int = 0
    column: int = 0
    taint_sources: list[str] = field(default_factory=list)

    def mark_tainted(self, source: str) -> None:
        self.is_tainted = True
        if source not in self.taint_sources:
            self.taint_sources.append(source)


@dataclass(frozen=True)
class SemanticIssue:
    message: str
    line: int
    column: int
    name: str = ""

