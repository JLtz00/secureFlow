"""Generate three-address code from SecureFlow's custom AST."""

from __future__ import annotations

from analyzer import ast_nodes as ast
from analyzer.ir import (
    Assign,
    BinaryOp,
    BuildCollection,
    Call,
    ConditionalJump,
    IRFunction,
    IRModule,
    Jump,
    Label,
    Return,
)


class IRGenerator:
    def __init__(self) -> None:
        self.module = IRModule()
        self.current = self.module.main
        self.temp_counter = 0
        self.label_counter = 0

    def generate(self, program: ast.Program) -> IRModule:
        for statement in program.body:
            if isinstance(statement, ast.FunctionDef):
                self._generate_function(statement)
            else:
                self._statement(statement)
        return self.module

    def _generate_function(self, node: ast.FunctionDef) -> None:
        previous = self.current
        function = IRFunction(node.name, list(node.params))
        self.module.functions[node.name] = function
        self.current = function
        for statement in node.body:
            self._statement(statement)
        if not function.instructions or not isinstance(function.instructions[-1], Return):
            function.instructions.append(Return(line=node.line))
        self.current = previous

    def _statement(self, node: ast.Statement) -> None:
        if isinstance(node, ast.Assign):
            value = self._expression(node.value)
            self._emit(Assign(line=node.line, target=node.target.name, value=value))
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
            return node.name
        if isinstance(node, ast.Literal):
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
        if isinstance(node, ast.CallExpr):
            function = self._expression(node.callee)
            args = [self._expression(arg) for arg in node.args]
            target = None if discard else self._new_temp()
            self._emit(Call(line=node.line, function=function, args=args, target=target))
            return target or "<discarded>"
        return "<unknown>"

    def _emit(self, instruction) -> None:
        self.current.instructions.append(instruction)

    def _new_temp(self) -> str:
        self.temp_counter += 1
        return f"t{self.temp_counter}"

    def _new_label(self, prefix: str) -> str:
        self.label_counter += 1
        return f"{prefix}_{self.label_counter}"


def generate_ir(program: ast.Program) -> IRModule:
    return IRGenerator().generate(program)
