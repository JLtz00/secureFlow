"""Custom AST node hierarchy for SecureFlow."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SourceLocation:
    line: int
    column: int


@dataclass
class ASTNode:
    location: SourceLocation

    @property
    def line(self) -> int:
        return self.location.line

    @property
    def column(self) -> int:
        return self.location.column

    def children(self) -> list["ASTNode"]:
        return []


@dataclass
class Statement(ASTNode):
    pass


@dataclass
class Expression(ASTNode):
    pass


@dataclass
class Program(ASTNode):
    body: list[Statement] = field(default_factory=list)

    def children(self) -> list[ASTNode]:
        return list(self.body)


@dataclass
class FunctionDef(Statement):
    name: str
    params: list[str]
    body: list[Statement]

    def children(self) -> list[ASTNode]:
        return list(self.body)


@dataclass
class Assign(Statement):
    target: "Identifier"
    value: Expression

    def children(self) -> list[ASTNode]:
        return [self.target, self.value]


@dataclass
class IfStmt(Statement):
    condition: Expression
    body: list[Statement]
    else_body: list[Statement] = field(default_factory=list)

    def children(self) -> list[ASTNode]:
        return [self.condition, *self.body, *self.else_body]


@dataclass
class WhileStmt(Statement):
    condition: Expression
    body: list[Statement]

    def children(self) -> list[ASTNode]:
        return [self.condition, *self.body]


@dataclass
class ForStmt(Statement):
    target: "Identifier"
    iterable: Expression
    body: list[Statement]

    def children(self) -> list[ASTNode]:
        return [self.target, self.iterable, *self.body]


@dataclass
class ReturnStmt(Statement):
    value: Expression | None = None

    def children(self) -> list[ASTNode]:
        return [] if self.value is None else [self.value]


@dataclass
class ExprStmt(Statement):
    expression: Expression

    def children(self) -> list[ASTNode]:
        return [self.expression]


@dataclass
class CallExpr(Expression):
    callee: Expression
    args: list[Expression] = field(default_factory=list)

    def children(self) -> list[ASTNode]:
        return [self.callee, *self.args]


@dataclass
class BinaryExpr(Expression):
    left: Expression
    operator: str
    right: Expression

    def children(self) -> list[ASTNode]:
        return [self.left, self.right]


@dataclass
class Identifier(Expression):
    name: str


@dataclass
class Literal(Expression):
    value: Any
    raw: str


@dataclass
class CollectionExpr(Expression):
    kind: str
    elements: list[Expression] = field(default_factory=list)

    def children(self) -> list[ASTNode]:
        return list(self.elements)


@dataclass
class ParseErrorNode(Statement):
    message: str
    token_value: str
