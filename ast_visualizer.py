"""Text visualizer for SecureFlow ASTs."""

from __future__ import annotations

from ast_nodes import (
    Assign,
    ASTNode,
    BinaryExpr,
    CallExpr,
    ExprStmt,
    ForStmt,
    FunctionDef,
    Identifier,
    IfStmt,
    Literal,
    ParseErrorNode,
    Program,
    ReturnStmt,
    WhileStmt,
)
from parser import parse_with_errors


def visualize(node: ASTNode) -> str:
    lines: list[str] = []
    _visit(node, lines, "", True)
    return "\n".join(lines)


def _visit(node: ASTNode, lines: list[str], prefix: str, is_last: bool) -> None:
    connector = "`-- " if is_last else "|-- "
    lines.append(f"{prefix}{connector}{_label(node)}")
    child_prefix = prefix + ("    " if is_last else "|   ")
    children = node.children()
    for index, child in enumerate(children):
        _visit(child, lines, child_prefix, index == len(children) - 1)


def _label(node: ASTNode) -> str:
    location = f"@{node.location.line}:{node.location.column}"
    if isinstance(node, Program):
        return f"Program {location}"
    if isinstance(node, FunctionDef):
        params = ", ".join(node.params)
        return f"FunctionDef name={node.name} params=({params}) {location}"
    if isinstance(node, Assign):
        return f"Assign target={node.target.name} {location}"
    if isinstance(node, IfStmt):
        return f"IfStmt {location}"
    if isinstance(node, WhileStmt):
        return f"WhileStmt {location}"
    if isinstance(node, ForStmt):
        return f"ForStmt target={node.target.name} {location}"
    if isinstance(node, ReturnStmt):
        return f"ReturnStmt {location}"
    if isinstance(node, ExprStmt):
        return f"ExprStmt {location}"
    if isinstance(node, CallExpr):
        return f"CallExpr {location}"
    if isinstance(node, BinaryExpr):
        return f"BinaryExpr operator={node.operator} {location}"
    if isinstance(node, Identifier):
        return f"Identifier name={node.name} {location}"
    if isinstance(node, Literal):
        return f"Literal raw={node.raw!r} value={node.value!r} {location}"
    if isinstance(node, ParseErrorNode):
        return f"ParseError message={node.message!r} token={node.token_value!r} {location}"
    return f"{node.__class__.__name__} {location}"


def visualize_source(source: str) -> str:
    program, errors = parse_with_errors(source)
    output = visualize(program)
    if errors:
        error_lines = ["", "Errors:"]
        for error in errors:
            error_lines.append(
                f"- {error.line}:{error.column}: {error.message} near {error.token_value!r}"
            )
        output += "\n" + "\n".join(error_lines)
    return output


if __name__ == "__main__":
    demo = """def get_user():
    user = request.args.get("user")
    return user

query = "SELECT * FROM users WHERE name='" + get_user()
cursor.execute(query)
"""
    print(visualize_source(demo))

