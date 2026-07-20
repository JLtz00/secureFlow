"""Semantic analysis for SecureFlow's custom AST."""

from __future__ import annotations

from dataclasses import dataclass, field

from analyzer.ast_nodes import (
    Assign,
    BinaryExpr,
    CallExpr,
    CollectionExpr,
    ExprStmt,
    Expression,
    ForStmt,
    FunctionDef,
    Identifier,
    IfStmt,
    ImportStmt,
    Literal,
    Program,
    ReturnStmt,
    Statement,
    WhileStmt,
)
from analyzer.parser import Parser
from analyzer.scope import Scope, SymbolTable
from analyzer.symbols import SemanticIssue, Symbol


TAINT_SOURCES = {"request.args.get", "request.form.get", "input"}
SANITIZERS = {"sanitize", "escape"}


@dataclass
class ExpressionInfo:
    type_name: str = "unknown"
    is_tainted: bool = False
    taint_sources: list[str] = field(default_factory=list)

    @classmethod
    def tainted(cls, type_name: str, source: str) -> "ExpressionInfo":
        return cls(type_name=type_name, is_tainted=True, taint_sources=[source])

    def merge(self, other: "ExpressionInfo") -> "ExpressionInfo":
        sources = list(dict.fromkeys([*self.taint_sources, *other.taint_sources]))
        type_name = self.type_name if self.type_name == other.type_name else "unknown"
        return ExpressionInfo(
            type_name=type_name,
            is_tainted=self.is_tainted or other.is_tainted,
            taint_sources=sources,
        )


@dataclass
class SemanticResult:
    symbols: SymbolTable
    issues: list[SemanticIssue]

    @property
    def tainted_symbols(self) -> list[Symbol]:
        return [symbol for symbol in self.symbols.all_symbols() if symbol.is_tainted]


class SemanticAnalyzer:
    """Builds scopes, resolves names, infers simple types and marks initial taint."""

    def __init__(self) -> None:
        self.symbol_table = SymbolTable()
        self.issues: list[SemanticIssue] = []

    def analyze(self, program: Program) -> SemanticResult:
        self._analyze_block(program.body, self.symbol_table.global_scope)
        return SemanticResult(symbols=self.symbol_table, issues=self.issues)

    def _analyze_block(self, statements: list[Statement], scope: Scope) -> None:
        for statement in statements:
            self._analyze_statement(statement, scope)

    def _analyze_statement(self, statement: Statement, scope: Scope) -> None:
        if isinstance(statement, FunctionDef):
            self._analyze_function(statement, scope)
        elif isinstance(statement, ImportStmt):
            return
        elif isinstance(statement, Assign):
            self._analyze_assign(statement, scope)
        elif isinstance(statement, IfStmt):
            self._analyze_expression(statement.condition, scope)
            self._analyze_block(statement.body, scope.create_child(f"if@{statement.line}", "block"))
            if statement.else_body:
                self._analyze_block(
                    statement.else_body,
                    scope.create_child(f"else@{statement.line}", "block"),
                )
        elif isinstance(statement, WhileStmt):
            self._analyze_expression(statement.condition, scope)
            self._analyze_block(statement.body, scope.create_child(f"while@{statement.line}", "block"))
        elif isinstance(statement, ForStmt):
            iterable_info = self._analyze_expression(statement.iterable, scope)
            block_scope = scope.create_child(f"for@{statement.line}", "block")
            self._define_or_update(
                statement.target.name,
                "variable",
                "unknown",
                iterable_info,
                block_scope,
                statement.target.line,
                statement.target.column,
            )
            self._analyze_block(statement.body, block_scope)
        elif isinstance(statement, ReturnStmt):
            if statement.value is not None:
                self._analyze_expression(statement.value, scope)
        elif isinstance(statement, ExprStmt):
            self._analyze_expression(statement.expression, scope)

    def _analyze_function(self, statement: FunctionDef, scope: Scope) -> None:
        function_symbol = Symbol(
            name=statement.name,
            kind="function",
            type_name="function",
            scope_name=scope.name,
            line=statement.line,
            column=statement.column,
        )
        scope.define(function_symbol)

        function_scope = scope.create_child(statement.name, "function")
        for param in statement.params:
            function_scope.define(
                Symbol(
                    name=param,
                    kind="parameter",
                    type_name="unknown",
                    scope_name=function_scope.name,
                    line=statement.line,
                    column=statement.column,
                )
            )
        self._analyze_block(statement.body, function_scope)

    def _analyze_assign(self, statement: Assign, scope: Scope) -> None:
        value_info = self._analyze_expression(statement.value, scope)
        self._define_or_update(
            statement.target.name,
            "variable",
            value_info.type_name,
            value_info,
            scope,
            statement.target.line,
            statement.target.column,
        )

    def _define_or_update(
        self,
        name: str,
        kind: str,
        type_name: str,
        value_info: ExpressionInfo,
        scope: Scope,
        line: int,
        column: int,
    ) -> Symbol:
        symbol = scope.resolve_local(name)
        if symbol is None:
            symbol = Symbol(
                name=name,
                kind=kind,
                type_name=type_name,
                scope_name=scope.name,
                line=line,
                column=column,
            )
            scope.define(symbol)
        else:
            symbol.type_name = type_name
            symbol.line = line
            symbol.column = column

        if value_info.is_tainted:
            for source in value_info.taint_sources:
                symbol.mark_tainted(source)
        return symbol

    def _analyze_expression(self, expression: Expression, scope: Scope) -> ExpressionInfo:
        if isinstance(expression, Literal):
            return ExpressionInfo(type_name=self._literal_type(expression))

        if isinstance(expression, Identifier):
            symbol = scope.resolve(expression.name)
            if symbol is None and "." not in expression.name:
                self.issues.append(
                    SemanticIssue(
                        message="Name used before assignment",
                        line=expression.line,
                        column=expression.column,
                        name=expression.name,
                    )
                )
                return ExpressionInfo()
            if symbol is None:
                return ExpressionInfo(type_name="callable")
            return ExpressionInfo(
                type_name=symbol.type_name,
                is_tainted=symbol.is_tainted,
                taint_sources=list(symbol.taint_sources),
            )

        if isinstance(expression, BinaryExpr):
            left = self._analyze_expression(expression.left, scope)
            right = self._analyze_expression(expression.right, scope)
            info = left.merge(right)
            if expression.operator == "+" and (
                left.type_name == "str" or right.type_name == "str"
            ):
                info.type_name = "str"
            return info

        if isinstance(expression, CallExpr):
            return self._analyze_call(expression, scope)

        if isinstance(expression, CollectionExpr):
            info = ExpressionInfo()
            for element in expression.elements:
                info = info.merge(self._analyze_expression(element, scope))
            return info

        return ExpressionInfo()

    def _analyze_call(self, expression: CallExpr, scope: Scope) -> ExpressionInfo:
        callee_name = self._callee_name(expression)
        arg_info = ExpressionInfo()
        for arg in expression.args:
            arg_info = arg_info.merge(self._analyze_expression(arg, scope))

        if callee_name in TAINT_SOURCES:
            return ExpressionInfo.tainted("str", callee_name)
        if callee_name in SANITIZERS:
            return ExpressionInfo(type_name="str", is_tainted=False)

        symbol = scope.resolve(callee_name)
        if symbol is not None and symbol.is_tainted:
            return ExpressionInfo(
                type_name=symbol.type_name,
                is_tainted=True,
                taint_sources=list(symbol.taint_sources),
            )

        return ExpressionInfo(
            type_name="unknown",
            is_tainted=arg_info.is_tainted,
            taint_sources=arg_info.taint_sources,
        )

    def _callee_name(self, expression: CallExpr) -> str:
        if isinstance(expression.callee, Identifier):
            return expression.callee.name
        return ""

    def _literal_type(self, literal: Literal) -> str:
        if isinstance(literal.value, bool):
            return "bool"
        if isinstance(literal.value, int):
            return "int"
        if isinstance(literal.value, float):
            return "float"
        if literal.value is None:
            return "none"
        return "str"


def analyze(program: Program) -> SemanticResult:
    return SemanticAnalyzer().analyze(program)


def analyze_source(source: str) -> SemanticResult:
    parser = Parser.from_source(source)
    program = parser.parse()
    result = analyze(program)
    for error in parser.errors:
        result.issues.append(
            SemanticIssue(
                message=f"Parse error: {error.message}",
                line=error.line,
                column=error.column,
                name=error.token_value,
            )
        )
    return result
