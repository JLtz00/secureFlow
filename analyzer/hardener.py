"""Automatic hardening: converts unsafe string-concatenation SQL calls
to parameterized queries.

Handles the pattern:
    cursor.execute("SQL..." + var [+ "SQL..."])
    engine.execute("SQL..." + var [+ "SQL..."])

Transforms to:
    cursor.execute("SQL... ?", (var,))
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Matches a single token in a + expression: either a quoted string or an identifier
_TOKEN = re.compile(r'"[^"]*"|\'[^\']*\'|\w+(?:\.\w+)*')

# Matches a full execute() call on one line (most common case)
_EXEC_LINE = re.compile(
    r'^(?P<indent>\s*)'
    r'(?P<sink>(?:cursor|engine)\.execute)\('
    r'(?P<arg>.+)'
    r'\)'
    r'(?P<trail>\s*)$'
)


@dataclass
class HardenedResult:
    source: str
    changes_made: int = 0
    modified_lines: list[int] = field(default_factory=list)

    @property
    def was_modified(self) -> bool:
        return self.changes_made > 0


class Hardener:
    """Transforms SQL injection-prone execute() calls into parameterized form."""

    def harden(self, source: str) -> HardenedResult:
        lines = source.splitlines(keepends=True)
        out_lines: list[str] = []
        changes = 0
        modified: list[int] = []

        for lineno, line in enumerate(lines, start=1):
            hardened, changed = self._harden_line(line)
            out_lines.append(hardened)
            if changed:
                changes += 1
                modified.append(lineno)

        return HardenedResult(
            source="".join(out_lines),
            changes_made=changes,
            modified_lines=modified,
        )

    def _harden_line(self, line: str) -> tuple[str, bool]:
        m = _EXEC_LINE.match(line.rstrip("\n"))
        if m is None:
            return line, False

        arg = m.group("arg").strip()
        parsed = self._parse_concat(arg)
        if parsed is None:
            return line, False

        template, params = parsed
        params_repr = f"({', '.join(params)},)" if len(params) == 1 else f"({', '.join(params)})"
        newline = (
            f"{m.group('indent')}"
            f"{m.group('sink')}({template}, {params_repr})"
            f"{m.group('trail')}\n"
        )
        return newline, True

    def _parse_concat(self, expr: str) -> tuple[str, list[str]] | None:
        """Split a + expression into (sql_template, [variable_names]).

        Returns None if there are no variable parts (no injection risk).
        """
        tokens = _TOKEN.findall(expr)
        if len(tokens) < 2:
            return None

        sql_parts: list[str] = []
        variables: list[str] = []

        for token in tokens:
            if (token.startswith('"') and token.endswith('"')) or (
                token.startswith("'") and token.endswith("'")
            ):
                sql_parts.append(token[1:-1])
            else:
                sql_parts.append("?")
                variables.append(token)

        if not variables:
            return None

        quote = '"'
        template = f"{quote}{''.join(sql_parts)}{quote}"
        return template, variables


def harden_source(source: str) -> HardenedResult:
    return Hardener().harden(source)
