"""Production frontend backed by Python's built-in ast parser.

The handwritten SecureFlow parser is useful for explaining compiler phases.
This frontend is intended for production scans: CPython parses full Python
syntax, then this adapter lowers the relevant constructs into SecureFlow's
custom AST so the existing IR/CFG/taint pipeline can be reused.
"""

from __future__ import annotations

import ast as pyast
from dataclasses import dataclass, field

from analyzer import ast_nodes as sf


@dataclass(frozen=True)
class FrontendError:
    message: str
    line: int
    column: int
    token_value: str = ""


@dataclass(frozen=True)
class CoverageIssue:
    node: str
    line: int
    status: str
    detail: str


@dataclass
class FrontendCoverage:
    total_nodes: int = 0
    supported_nodes: int = 0
    approximated_nodes: int = 0
    ignored_nodes: int = 0
    issues: list[CoverageIssue] = field(default_factory=list)

    @property
    def coverage_ratio(self) -> float:
        if self.total_nodes == 0:
            return 1.0
        return (self.supported_nodes + self.approximated_nodes) / self.total_nodes


@dataclass
class FrontendResult:
    program: sf.Program
    errors: list[FrontendError] = field(default_factory=list)
    coverage: FrontendCoverage = field(default_factory=FrontendCoverage)


class PythonAstFrontend:
    """Lower CPython AST nodes to SecureFlow AST nodes."""

    def parse(self, source: str, filename: str = "<unknown>") -> FrontendResult:
        self.coverage = FrontendCoverage()
        try:
            tree = pyast.parse(source, filename=filename)
        except SyntaxError as exc:
            location = sf.SourceLocation(exc.lineno or 1, exc.offset or 1)
            program = sf.Program(location=location, body=[])
            return FrontendResult(
                program=program,
                errors=[
                    FrontendError(
                        message=exc.msg,
                        line=exc.lineno or 1,
                        column=exc.offset or 1,
                        token_value=(exc.text or "").strip(),
                    )
                ],
                coverage=self.coverage,
            )

        body = self._statements(tree.body)
        return FrontendResult(
            program=sf.Program(location=sf.SourceLocation(1, 1), body=body),
            errors=[],
            coverage=self.coverage,
        )

    def _statements(self, nodes: list[pyast.stmt]) -> list[sf.Statement]:
        statements: list[sf.Statement] = []
        for node in nodes:
            if isinstance(node, pyast.ClassDef):
                self._approximated(
                    node,
                    "methods are lowered with qualified names; inheritance, descriptors and class-body execution are approximated",
                )
                statements.extend(self._class_methods(node))
                continue
            statement = self._statement(node)
            if statement is not None:
                statements.append(statement)
        return statements

    def _class_methods(self, node: pyast.ClassDef) -> list[sf.Statement]:
        methods: list[sf.Statement] = []
        for item in node.body:
            if isinstance(item, (pyast.FunctionDef, pyast.AsyncFunctionDef)):
                function = self._statement(item)
                if isinstance(function, sf.FunctionDef):
                    function.name = f"{node.name}.{function.name}"
                    methods.append(function)
        return methods

    def _statement(self, node: pyast.stmt) -> sf.Statement | None:
        location = self._location(node)

        if isinstance(node, (pyast.Import, pyast.ImportFrom)):
            self._supported(node)
            return self._import(node)

        if isinstance(node, (pyast.FunctionDef, pyast.AsyncFunctionDef)):
            if node.decorator_list or isinstance(node, pyast.AsyncFunctionDef):
                self._approximated(node, "decorators/async scheduling do not alter taint flow")
            else:
                self._supported(node)
            return sf.FunctionDef(
                location=location,
                name=node.name,
                params=[arg.arg for arg in node.args.args],
                body=self._statements(node.body),
            )

        if isinstance(node, pyast.Assign):
            self._supported(node)
            if not node.targets:
                return None
            target = self._target_name(node.targets[0])
            return sf.Assign(
                location=location,
                target=sf.Identifier(location=location, name=target),
                value=self._expression(node.value),
            )

        if isinstance(node, pyast.AnnAssign):
            self._supported(node)
            target = self._target_name(node.target)
            value = node.value or pyast.Constant(value=None, lineno=node.lineno, col_offset=node.col_offset)
            return sf.Assign(
                location=location,
                target=sf.Identifier(location=location, name=target),
                value=self._expression(value),
            )

        if isinstance(node, pyast.AugAssign):
            self._supported(node)
            target = self._target_name(node.target)
            target_expr = sf.Identifier(location=location, name=target)
            return sf.Assign(
                location=location,
                target=target_expr,
                value=sf.BinaryExpr(
                    location=location,
                    left=target_expr,
                    operator=self._operator(node.op),
                    right=self._expression(node.value),
                ),
            )

        if isinstance(node, pyast.Return):
            self._supported(node)
            return sf.ReturnStmt(
                location=location,
                value=None if node.value is None else self._expression(node.value),
            )

        if isinstance(node, pyast.Expr):
            self._supported(node)
            return sf.ExprStmt(location=location, expression=self._expression(node.value))

        if isinstance(node, pyast.If):
            self._supported(node)
            return sf.IfStmt(
                location=location,
                condition=self._expression(node.test),
                body=self._statements(node.body),
                else_body=self._statements(node.orelse),
            )

        if isinstance(node, pyast.While):
            self._supported(node)
            return sf.WhileStmt(
                location=location,
                condition=self._expression(node.test),
                body=self._statements(node.body),
            )

        if isinstance(node, pyast.For):
            self._supported(node)
            return sf.ForStmt(
                location=location,
                target=sf.Identifier(location=location, name=self._target_name(node.target)),
                iterable=self._expression(node.iter),
                body=self._statements(node.body),
            )

        if isinstance(node, pyast.With):
            self._approximated(node, "context-manager enter/exit calls are not modeled")
            return sf.IfStmt(
                location=location,
                condition=sf.Literal(location=location, value=True, raw="True"),
                body=self._statements(node.body),
                else_body=[],
            )

        if isinstance(node, pyast.Try):
            self._approximated(node, "exceptional paths are conservatively merged")
            body = self._statements(node.body)
            for handler in node.handlers:
                body.extend(self._statements(handler.body))
            body.extend(self._statements(node.orelse))
            body.extend(self._statements(node.finalbody))
            return sf.IfStmt(
                location=location,
                condition=sf.Literal(location=location, value=True, raw="True"),
                body=body,
                else_body=[],
            )

        if isinstance(node, pyast.Raise):
            self._approximated(node, "exception termination is covered by the enclosing conservative merge")
            expression = node.exc or pyast.Constant(
                value=None,
                lineno=getattr(node, "lineno", 1),
                col_offset=getattr(node, "col_offset", 0),
            )
            return sf.ExprStmt(location=location, expression=self._expression(expression))

        if isinstance(node, pyast.Pass):
            self._supported(node)
            return sf.ExprStmt(
                location=location,
                expression=sf.Literal(location=location, value=None, raw="None"),
            )

        if isinstance(node, pyast.Continue):
            self._approximated(
                node,
                "continue is lowered as a no-op, conservatively retaining the remaining flow",
            )
            return sf.ExprStmt(
                location=location,
                expression=sf.Literal(location=location, value=None, raw="None"),
            )

        self._ignored(node, "statement has no SecureFlow IR lowering")
        return None

    def _import(self, node: pyast.Import | pyast.ImportFrom) -> sf.ImportStmt:
        location = self._location(node)
        aliases: dict[str, str] = {}
        if isinstance(node, pyast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                aliases[local] = alias.name if alias.asname else local
            return sf.ImportStmt(location=location, module=None, aliases=aliases)

        module = node.module or ""
        if node.level:
            module = "." * node.level + module
        for alias in node.names:
            local = alias.asname or alias.name
            aliases[local] = f"{module}.{alias.name}" if module else alias.name
        return sf.ImportStmt(location=location, module=module, aliases=aliases)

    def _expression(self, node: pyast.AST) -> sf.Expression:
        location = self._location(node)

        if isinstance(node, pyast.Name):
            self._supported(node)
            return sf.Identifier(location=location, name=node.id)

        if isinstance(node, pyast.Attribute):
            self._supported(node)
            return sf.Identifier(location=location, name=self._expr_name(node))

        if isinstance(node, pyast.Constant):
            self._supported(node)
            raw = repr(node.value) if isinstance(node.value, str) else str(node.value)
            if node.value is None:
                raw = "None"
            return sf.Literal(location=location, value=node.value, raw=raw)

        if isinstance(node, pyast.JoinedStr):
            self._supported(node)
            return sf.Literal(location=location, value="<fstring>", raw=self._fstring_raw(node))

        if isinstance(node, pyast.BinOp):
            self._supported(node)
            return sf.BinaryExpr(
                location=location,
                left=self._expression(node.left),
                operator=self._operator(node.op),
                right=self._expression(node.right),
            )

        if isinstance(node, pyast.BoolOp):
            self._supported(node)
            values = list(node.values)
            if not values:
                return sf.Literal(location=location, value=False, raw="False")
            expr = self._expression(values[0])
            for value in values[1:]:
                expr = sf.BinaryExpr(
                    location=location,
                    left=expr,
                    operator="and" if isinstance(node.op, pyast.And) else "or",
                    right=self._expression(value),
                )
            return expr

        if isinstance(node, pyast.Compare):
            self._supported(node)
            if not node.ops or not node.comparators:
                return self._expression(node.left)
            return sf.BinaryExpr(
                location=location,
                left=self._expression(node.left),
                operator=self._operator(node.ops[0]),
                right=self._expression(node.comparators[0]),
            )

        if isinstance(node, pyast.Call):
            self._supported(node)
            callee = self._expression(node.func)
            args = [self._expression(arg) for arg in node.args]
            args.extend(self._expression(keyword.value) for keyword in node.keywords if keyword.value is not None)
            return sf.CallExpr(location=location, callee=callee, args=args)

        if isinstance(node, pyast.Subscript):
            self._supported(node)
            return sf.SubscriptExpr(
                location=location,
                collection=self._expression(node.value),
                index=self._expression(node.slice),
            )

        if isinstance(node, (pyast.List, pyast.Tuple, pyast.Set)):
            self._supported(node)
            kind = "tuple" if isinstance(node, pyast.Tuple) else "list"
            return sf.CollectionExpr(
                location=location,
                kind=kind,
                elements=[self._expression(element) for element in node.elts],
            )

        if isinstance(node, pyast.Dict):
            self._supported(node)
            return sf.CollectionExpr(
                location=location,
                kind="dict",
                elements=[self._expression(value) for value in node.values if value is not None],
            )

        if isinstance(node, pyast.UnaryOp):
            self._supported(node)
            return self._expression(node.operand)

        if isinstance(node, pyast.IfExp):
            self._approximated(
                node,
                "conditional expression branches are merged conservatively",
            )
            return sf.CollectionExpr(
                location=location,
                kind="conditional",
                elements=[
                    self._expression(node.body),
                    self._expression(node.orelse),
                ],
            )

        if isinstance(node, (pyast.ListComp, pyast.SetComp, pyast.GeneratorExp)):
            self._approximated(
                node,
                "comprehension iteration is summarized as a conservative collection",
            )
            elements = [self._expression(node.elt)]
            elements.extend(self._comprehension_inputs(node.generators))
            return sf.CollectionExpr(
                location=location,
                kind="comprehension",
                elements=elements,
            )

        if isinstance(node, pyast.DictComp):
            self._approximated(
                node,
                "dictionary comprehension is summarized as a conservative collection",
            )
            return sf.CollectionExpr(
                location=location,
                kind="dict_comprehension",
                elements=[
                    self._expression(node.key),
                    self._expression(node.value),
                    *self._comprehension_inputs(node.generators),
                ],
            )

        if isinstance(node, pyast.Starred):
            self._approximated(
                node,
                "starred expansion preserves the value flow without cardinality",
            )
            return self._expression(node.value)

        if isinstance(node, pyast.Slice):
            self._approximated(
                node,
                "slice bounds are merged conservatively into the subscript value",
            )
            parts = [
                part
                for part in (node.lower, node.upper, node.step)
                if part is not None
            ]
            return sf.CollectionExpr(
                location=location,
                kind="slice",
                elements=[self._expression(part) for part in parts],
            )

        if isinstance(node, pyast.Lambda):
            self._approximated(
                node,
                "lambda body value flow is preserved without a callable summary",
            )
            return self._expression(node.body)

        if isinstance(node, (pyast.Yield, pyast.YieldFrom)):
            self._approximated(
                node,
                "yield suspension is ignored while yielded value flow is preserved",
            )
            if node.value is None:
                return sf.Literal(location=location, value=None, raw="None")
            return self._expression(node.value)

        if isinstance(node, pyast.Await):
            self._approximated(node, "await scheduling is ignored; value flow is preserved")
            return self._expression(node.value)

        self._ignored(node, "expression replaced with an unknown literal")
        return sf.Literal(location=location, value=None, raw="<unsupported>")

    def _comprehension_inputs(
        self,
        generators: list[pyast.comprehension],
    ) -> list[sf.Expression]:
        inputs: list[sf.Expression] = []
        for generator in generators:
            inputs.append(self._expression(generator.iter))
            inputs.extend(self._expression(condition) for condition in generator.ifs)
        return inputs

    def _target_name(self, node: pyast.AST) -> str:
        if isinstance(node, pyast.Name):
            return node.id
        return self._expr_name(node)

    def _expr_name(self, node: pyast.AST) -> str:
        if isinstance(node, pyast.Name):
            return node.id
        if isinstance(node, pyast.Attribute):
            base = self._expr_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, pyast.Call):
            return self._expr_name(node.func)
        if isinstance(node, pyast.Subscript):
            base = self._expr_name(node.value)
            index = self._expr_name(node.slice)
            return f"{base}[{index}]" if base else f"[{index}]"
        if isinstance(node, pyast.Constant):
            return repr(node.value) if isinstance(node.value, str) else str(node.value)
        return "<expr>"

    def _supported(self, node: pyast.AST) -> None:
        self.coverage.total_nodes += 1
        self.coverage.supported_nodes += 1

    def _approximated(self, node: pyast.AST, detail: str) -> None:
        self.coverage.total_nodes += 1
        self.coverage.approximated_nodes += 1
        self.coverage.issues.append(
            CoverageIssue(type(node).__name__, getattr(node, "lineno", 1) or 1, "approximated", detail)
        )

    def _ignored(self, node: pyast.AST, detail: str) -> None:
        self.coverage.total_nodes += 1
        self.coverage.ignored_nodes += 1
        self.coverage.issues.append(
            CoverageIssue(type(node).__name__, getattr(node, "lineno", 1) or 1, "ignored", detail)
        )

    def _fstring_raw(self, node: pyast.JoinedStr) -> str:
        fields = [
            self._expr_name(value.value)
            for value in node.values
            if isinstance(value, pyast.FormattedValue)
        ]
        return 'f"' + " ".join(f"{{{field}}}" for field in fields) + '"'

    def _operator(self, op: pyast.AST) -> str:
        return {
            pyast.Add: "+",
            pyast.Sub: "-",
            pyast.Mult: "*",
            pyast.Div: "/",
            pyast.FloorDiv: "//",
            pyast.Mod: "%",
            pyast.Eq: "==",
            pyast.NotEq: "!=",
            pyast.Lt: "<",
            pyast.LtE: "<=",
            pyast.Gt: ">",
            pyast.GtE: ">=",
            pyast.In: "in",
            pyast.Is: "is",
        }.get(type(op), "")

    def _location(self, node: pyast.AST) -> sf.SourceLocation:
        return sf.SourceLocation(
            line=getattr(node, "lineno", 1) or 1,
            column=(getattr(node, "col_offset", 0) or 0) + 1,
        )


def parse_python_ast(source: str, filename: str = "<unknown>") -> FrontendResult:
    return PythonAstFrontend().parse(source, filename=filename)
