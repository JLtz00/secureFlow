"""Automatic hardening for SQL string-concatenation sinks.

When LibCST is installed, SecureFlow rewrites common SQL concatenation
patterns while preserving formatting and emitting a unified diff. A small
regex fallback remains available for dependency-free classroom runs.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

try:  # pragma: no cover - availability depends on the execution environment
    import libcst as cst
except ImportError:  # pragma: no cover
    cst = None


_TOKEN = re.compile(r'"[^"]*"|\'[^\']*\'|\w+(?:\.\w+)*')
_EXEC_LINE = re.compile(
    r'^(?P<indent>\s*)'
    r'(?P<prefix>(?:return\s+)?)'
    r'(?P<sink>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.execute(?:many)?)\('
    r'(?P<arg>.+)'
    r'\)'
    r'(?P<trail>\s*)$'
)
_SINKS = {
    "cursor.execute",
    "cursor.executemany",
    "engine.execute",
    "engine.executemany",
    "connection.execute",
    "connection.executemany",
    "session.execute",
    "session.executemany",
    "db.session.execute",
    "db.session.executemany",
}


@dataclass
class HardenedResult:
    source: str
    changes_made: int = 0
    modified_lines: list[int] = field(default_factory=list)
    diff: str = ""
    engine: str = "regex"

    @property
    def was_modified(self) -> bool:
        return self.changes_made > 0


@dataclass(frozen=True)
class _SqlTemplate:
    template: str
    params: tuple[str, ...]


class Hardener:
    """Transforms SQL injection-prone execute() calls into parameterized form."""

    def harden(self, source: str) -> HardenedResult:
        if cst is not None:
            return self._harden_with_libcst(source)
        return self._harden_with_regex(source)

    def _harden_with_libcst(self, source: str) -> HardenedResult:
        try:
            module = cst.parse_module(source)
        except Exception:
            return self._harden_with_regex(source)

        transformer = _SqlHardeningTransformer()
        updated = module.visit(transformer)
        new_source = updated.code
        diff = _unified_diff(source, new_source)
        return HardenedResult(
            source=new_source,
            changes_made=transformer.changes,
            modified_lines=_modified_lines(diff),
            diff=diff,
            engine="libcst",
        )

    def _harden_with_regex(self, source: str) -> HardenedResult:
        lines = source.splitlines(keepends=True)
        out_lines: list[str] = []
        changes = 0
        modified: list[int] = []

        for lineno, line in enumerate(lines, start=1):
            hardened, changed = self._harden_line_regex(line)
            out_lines.append(hardened)
            if changed:
                changes += 1
                modified.append(lineno)

        new_source = "".join(out_lines)
        return HardenedResult(
            source=new_source,
            changes_made=changes,
            modified_lines=modified,
            diff=_unified_diff(source, new_source),
            engine="regex",
        )

    def _harden_line_regex(self, line: str) -> tuple[str, bool]:
        m = _EXEC_LINE.match(line.rstrip("\n"))
        if m is None:
            return line, False

        arg = m.group("arg").strip()
        parsed = _parse_concat_text(arg)
        if parsed is None:
            return line, False

        template, params = parsed
        params_repr = f"({', '.join(params)},)" if len(params) == 1 else f"({', '.join(params)})"
        newline = (
            f"{m.group('indent')}"
            f"{m.group('prefix')}"
            f"{m.group('sink')}({template}, {params_repr})"
            f"{m.group('trail')}\n"
        )
        return newline, True


if cst is not None:

    class _SqlHardeningTransformer(cst.CSTTransformer):
        def __init__(self) -> None:
            self.env: dict[str, _SqlTemplate] = {}
            self.changes = 0

        def leave_Assign(self, original_node, updated_node):
            if len(original_node.targets) != 1:
                return updated_node
            target = original_node.targets[0].target
            if not isinstance(target, cst.Name):
                return updated_node

            parsed = self._parse_expr(original_node.value)
            if parsed is None or not _looks_like_sql(parsed.template):
                self.env.pop(target.value, None)
                return updated_node

            self.env[target.value] = parsed
            if parsed.params:
                self.changes += 1
                return updated_node.with_changes(value=_string_expr(parsed.template))
            return updated_node

        def leave_Call(self, original_node, updated_node):
            if not original_node.args:
                return updated_node
            sink_name = self._qualified_name(original_node.func)
            if sink_name not in _SINKS and not _is_execute_method(sink_name):
                return updated_node
            if len(original_node.args) > 1:
                return updated_node

            parsed = self._parse_expr(original_node.args[0].value)
            if parsed is None or not parsed.params or not _looks_like_sql(parsed.template):
                return updated_node

            self.changes += 1
            query_expr = (
                updated_node.args[0].value
                if isinstance(original_node.args[0].value, cst.Name)
                else _string_expr(parsed.template)
            )
            return updated_node.with_changes(
                args=[
                    cst.Arg(query_expr),
                    cst.Arg(_tuple_expr(parsed.params)),
                ]
            )

        def _parse_expr(self, node) -> _SqlTemplate | None:
            if isinstance(node, cst.BinaryOperation) and isinstance(node.operator, cst.Add):
                left = self._parse_expr(node.left)
                right = self._parse_expr(node.right)
                if left is None or right is None:
                    return None
                return _SqlTemplate(left.template + right.template, left.params + right.params)

            if isinstance(node, cst.SimpleString):
                try:
                    return _SqlTemplate(str(node.evaluated_value), ())
                except Exception:
                    return None

            if isinstance(node, (cst.Integer, cst.Float, cst.Imaginary)):
                return None

            if isinstance(node, cst.FormattedString):
                params: list[str] = []
                template = ""
                for part in node.parts:
                    if isinstance(part, cst.FormattedStringText):
                        template += part.value
                    elif isinstance(part, cst.FormattedStringExpression):
                        params.append(cst.Module([]).code_for_node(part.expression))
                        template += "?"
                return _SqlTemplate(template, tuple(params))

            if isinstance(node, cst.Name) and node.value in self.env:
                return self.env[node.value]

            name = cst.Module([]).code_for_node(node).strip()
            if not name or name.startswith(('"', "'")):
                return None
            return _SqlTemplate("?", (name,))

        def _qualified_name(self, node) -> str:
            if isinstance(node, cst.Name):
                return node.value
            if isinstance(node, cst.Attribute):
                base = self._qualified_name(node.value)
                return f"{base}.{node.attr.value}" if base else node.attr.value
            return ""


def _string_expr(value: str):
    if cst is None:
        raise RuntimeError("LibCST is not available")
    return cst.SimpleString(repr(value))


def _tuple_expr(params: tuple[str, ...]):
    if cst is None:
        raise RuntimeError("LibCST is not available")
    return cst.Tuple([cst.Element(cst.parse_expression(param)) for param in params])


def _parse_concat_text(expr: str) -> tuple[str, list[str]] | None:
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
    template = "".join(sql_parts)
    if not _looks_like_sql(template):
        return None
    return f'"{template}"', variables


def _looks_like_sql(template: str) -> bool:
    return bool(
        re.search(
            r"\b(select|insert|update|delete|replace|with)\b",
            template,
            flags=re.IGNORECASE,
        )
    )


def _is_execute_method(function: str) -> bool:
    return function.endswith(".execute") or function.endswith(".executemany")


def _unified_diff(before: str, after: str) -> str:
    if before == after:
        return ""
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="before.py",
            tofile="after.py",
        )
    )


def _modified_lines(diff: str) -> list[int]:
    lines: list[int] = []
    current: int | None = None
    for line in diff.splitlines():
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            current = int(match.group(1)) if match else None
            continue
        if current is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(current)
            current += 1
        elif not line.startswith("-"):
            current += 1
    return lines


def harden_source(source: str) -> HardenedResult:
    return Hardener().harden(source)
