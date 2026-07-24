"""Generate three-address code from SecureFlow's custom AST."""

from __future__ import annotations

import re

from analyzer import ast_nodes as ast
from analyzer.framework_profiles import FrameworkProfile, get_profile
from analyzer.ir import (
    Assign,
    BinaryOp,
    BuildCollection,
    BuildFString,
    Call,
    ConditionalJump,
    IRFunction,
    IRModule,
    Jump,
    Label,
    Return,
    Subscript,
)


class IRGenerator:
    def __init__(self, profile: FrameworkProfile | None = None) -> None:
        self.module = IRModule()
        self.current = self.module.main
        self.temp_counter = 0
        self.label_counter = 0
        self.aliases: dict[str, str] = {}
        self.object_kinds: dict[str, str] = {}
        self.profile = profile or get_profile("base")

    def generate(self, program: ast.Program) -> IRModule:
        for statement in program.body:
            if isinstance(statement, ast.FunctionDef):
                self._generate_function(statement)
            elif isinstance(statement, ast.ImportStmt):
                self._register_import(statement)
            else:
                self._statement(statement)
        return self.module

    def _register_import(self, node: ast.ImportStmt) -> None:
        for local, qualified in node.aliases.items():
            if qualified == "flask.request":
                self.aliases[local] = "request"
            elif qualified == "sqlalchemy.text":
                self.aliases[local] = "sqlalchemy.text"
            else:
                self.aliases[local] = qualified

    def _generate_function(self, node: ast.FunctionDef) -> None:
        previous = self.current
        previous_object_kinds = self.object_kinds
        self.object_kinds = {}
        function = IRFunction(node.name, list(node.params))
        self.module.functions[node.name] = function
        self.current = function
        for statement in node.body:
            self._statement(statement)
        if not function.instructions or not isinstance(function.instructions[-1], Return):
            function.instructions.append(Return(line=node.line))
        self.current = previous
        self.object_kinds = previous_object_kinds

    def _statement(self, node: ast.Statement) -> None:
        if isinstance(node, ast.Assign):
            value = self._expression(node.value)
            self._emit(Assign(line=node.line, target=node.target.name, value=value))
            self._propagate_object_kind(node.target.name, value)
        elif isinstance(node, ast.ImportStmt):
            self._register_import(node)
        elif isinstance(node, ast.ExprStmt):
            self._expression(node.expression, discard=True)
        elif isinstance(node, ast.ReturnStmt):
            value = None if node.value is None else self._expression(node.value)
            self._emit(Return(line=node.line, value=value))
        elif isinstance(node, ast.IfStmt):
            self._if_statement(node)
        elif isinstance(node, ast.WhileStmt):
            self._while_statement(node)
        elif isinstance(node, ast.ForStmt):
            self._for_statement(node)

    def _if_statement(self, node: ast.IfStmt) -> None:
        condition = self._expression(node.condition)
        then_label = self._new_label("if_then")
        else_label = self._new_label("if_else")
        end_label = self._new_label("if_end")
        self._emit(
            ConditionalJump(
                line=node.line,
                condition=condition,
                true_target=then_label,
                false_target=else_label,
            )
        )
        self._emit(Label(line=node.line, name=then_label))
        for statement in node.body:
            self._statement(statement)
        if not self.current.instructions or not isinstance(
            self.current.instructions[-1], (Jump, Return)
        ):
            self._emit(Jump(line=node.line, target=end_label))
        self._emit(Label(line=node.line, name=else_label))
        for statement in node.else_body:
            self._statement(statement)
        self._emit(Label(line=node.line, name=end_label))

    def _while_statement(self, node: ast.WhileStmt) -> None:
        condition_label = self._new_label("while_condition")
        body_label = self._new_label("while_body")
        end_label = self._new_label("while_end")
        self._emit(Label(line=node.line, name=condition_label))
        condition = self._expression(node.condition)
        self._emit(
            ConditionalJump(
                line=node.line,
                condition=condition,
                true_target=body_label,
                false_target=end_label,
            )
        )
        self._emit(Label(line=node.line, name=body_label))
        for statement in node.body:
            self._statement(statement)
        self._emit(Jump(line=node.line, target=condition_label))
        self._emit(Label(line=node.line, name=end_label))

    def _for_statement(self, node: ast.ForStmt) -> None:
        iterable = self._expression(node.iterable)
        iterator = self._new_temp()
        self._emit(Call(line=node.line, function="iter", args=[iterable], target=iterator))
        condition_label = self._new_label("for_condition")
        body_label = self._new_label("for_body")
        end_label = self._new_label("for_end")
        self._emit(Label(line=node.line, name=condition_label))
        has_next = self._new_temp()
        self._emit(Call(line=node.line, function="has_next", args=[iterator], target=has_next))
        self._emit(
            ConditionalJump(
                line=node.line,
                condition=has_next,
                true_target=body_label,
                false_target=end_label,
            )
        )
        self._emit(Label(line=node.line, name=body_label))
        next_value = self._new_temp()
        self._emit(Call(line=node.line, function="next", args=[iterator], target=next_value))
        self._emit(Assign(line=node.line, target=node.target.name, value=next_value))
        for statement in node.body:
            self._statement(statement)
        self._emit(Jump(line=node.line, target=condition_label))
        self._emit(Label(line=node.line, name=end_label))

    def _expression(self, node: ast.Expression, discard: bool = False) -> str:
        if isinstance(node, ast.Identifier):
            return self._resolve_alias(node.name)
        if isinstance(node, ast.Literal):
            if isinstance(node.raw, str) and node.raw.lstrip("rRuUbB").lower().startswith("f"):
                fields = self._fstring_fields(node.raw)
                target = self._new_temp()
                self._emit(BuildFString(line=node.line, target=target, raw=node.raw, fields=fields))
                return target
            return node.raw
        if isinstance(node, ast.BinaryExpr):
            left = self._expression(node.left)
            right = self._expression(node.right)
            target = self._new_temp()
            self._emit(
                BinaryOp(
                    line=node.line,
                    target=target,
                    left=left,
                    operator=node.operator,
                    right=right,
                )
            )
            return target
        if isinstance(node, ast.CollectionExpr):
            elements = [self._expression(element) for element in node.elements]
            target = self._new_temp()
            self._emit(
                BuildCollection(
                    line=node.line,
                    target=target,
                    kind=node.kind,
                    elements=elements,
                )
            )
            return target
        if isinstance(node, ast.SubscriptExpr):
            collection = self._expression(node.collection)
            index = self._expression(node.index)
            target = self._new_temp()
            self._emit(
                Subscript(
                    line=node.line,
                    target=target,
                    collection=collection,
                    index=index,
                    access_path=self._access_path(node),
                )
            )
            return target
        if isinstance(node, ast.CallExpr):
            function = self._expression(node.callee)
            args = [self._expression(arg) for arg in node.args]
            target = None if discard else self._new_temp()
            receiver_kind = self._receiver_kind(function)
            canonical = self.profile.canonical_call(function, receiver_kind)
            return_kind = (
                self.profile.call_return_kind(function)
                or self.profile.method_return_kind(receiver_kind, function.rsplit(".", 1)[-1])
            )
            self._emit(
                Call(
                    line=node.line,
                    function=canonical,
                    args=args,
                    target=target,
                    return_kind=return_kind,
                )
            )
            if target is not None:
                if return_kind is not None:
                    self.object_kinds[target] = return_kind
            return target or "<discarded>"
        if isinstance(node, ast.MethodCallExpr):
            receiver = self._expression(node.receiver)
            args = [self._expression(arg) for arg in node.args]
            function = "str.format" if node.method == "format" else f"{receiver}.{node.method}"
            target = None if discard else self._new_temp()
            self._emit(
                Call(
                    line=node.line,
                    function=function,
                    args=[receiver, *args],
                    target=target,
                )
            )
            return target or "<discarded>"
        return "<unknown>"

    def _resolve_alias(self, name: str) -> str:
        head, _, tail = name.partition(".")
        qualified = self.aliases.get(head)
        if qualified is None:
            return name
        return qualified if not tail else f"{qualified}.{tail}"

    def _propagate_object_kind(self, target: str, value: str) -> None:
        kind = self.object_kinds.get(value)
        if kind is None:
            self.object_kinds.pop(target, None)
        else:
            self.object_kinds[target] = kind

    def _receiver_kind(self, function: str) -> str | None:
        if "." not in function:
            return None
        return self._kind_for_name(function.rsplit(".", 1)[0])

    def _kind_for_name(self, name: str) -> str | None:
        direct = self.object_kinds.get(name)
        if direct is not None:
            return direct
        head, *attributes = name.split(".")
        kind = self.object_kinds.get(head)
        for attribute in attributes:
            kind = self.profile.attribute_return_kind(kind, attribute)
            if kind is None:
                return None
        return kind

    def _access_path(self, node: ast.Expression) -> str | None:
        if isinstance(node, ast.Identifier):
            return self._resolve_alias(node.name)
        if isinstance(node, ast.SubscriptExpr):
            collection = self._access_path(node.collection)
            index = self._static_access_part(node.index)
            if collection is not None and index is not None:
                return f"{collection}[{index}]"
        return None

    def _static_access_part(self, node: ast.Expression) -> str | None:
        if isinstance(node, ast.Literal):
            return node.raw
        if isinstance(node, ast.Identifier):
            return self._resolve_alias(node.name)
        return None

    def _fstring_fields(self, raw: str) -> list[str]:
        return [
            self._resolve_alias(match.group(1).strip())
            for match in re.finditer(r"\{([A-Za-z_][A-Za-z0-9_\.]*)[^}]*\}", raw)
        ]

    def _emit(self, instruction) -> None:
        self.current.instructions.append(instruction)

    def _new_temp(self) -> str:
        self.temp_counter += 1
        return f"t{self.temp_counter}"

    def _new_label(self, prefix: str) -> str:
        self.label_counter += 1
        return f"{prefix}_{self.label_counter}"


def generate_ir(
    program: ast.Program,
    profile: FrameworkProfile | None = None,
) -> IRModule:
    return IRGenerator(profile=profile).generate(program)
