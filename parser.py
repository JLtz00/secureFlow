"""Recursive-descent parser for SecureFlow's Python subset."""

from __future__ import annotations

from dataclasses import dataclass

from ast_nodes import (
    Assign,
    BinaryExpr,
    CallExpr,
    ExprStmt,
    Expression,
    ForStmt,
    FunctionDef,
    Identifier,
    IfStmt,
    Literal,
    ParseErrorNode,
    Program,
    ReturnStmt,
    SourceLocation,
    Statement,
    WhileStmt,
)
from lexer import Lexer, Token, TokenType


@dataclass(frozen=True)
class ParseError:
    message: str
    line: int
    column: int
    token_value: str


class Parser:
    """LL-style recursive-descent parser with synchronization recovery."""

    PRECEDENCE = {
        "or": 1,
        "and": 2,
        "==": 3,
        "!=": 3,
        "<": 3,
        "<=": 3,
        ">": 3,
        ">=": 3,
        "in": 3,
        "is": 3,
        "+": 4,
        "-": 4,
        "*": 5,
        "/": 5,
        "//": 5,
        "%": 5,
    }

    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.current = 0
        self.errors: list[ParseError] = []

    @classmethod
    def from_source(cls, source: str) -> "Parser":
        return cls(Lexer().tokenize(source))

    def parse(self) -> Program:
        body: list[Statement] = []
        start = self._peek()
        self._skip_newlines()

        while not self._check(TokenType.EOF):
            statement = self._parse_statement()
            if statement is not None:
                body.append(statement)
            self._skip_newlines()

        return Program(location=self._location(start), body=body)

    def _parse_statement(self) -> Statement | None:
        if self._match_keyword("def"):
            return self._parse_function_def(self._previous())
        if self._match_keyword("if"):
            return self._parse_if_stmt(self._previous())
        if self._match_keyword("while"):
            return self._parse_while_stmt(self._previous())
        if self._match_keyword("for"):
            return self._parse_for_stmt(self._previous())
        if self._match_keyword("return"):
            return self._parse_return_stmt(self._previous())
        if self._check(TokenType.DEDENT):
            return None
        if self._check(TokenType.ERROR):
            return self._error_statement("Lexer error")

        return self._parse_simple_statement()

    def _parse_function_def(self, token: Token) -> FunctionDef:
        name = self._consume_identifier("Expected function name after 'def'")
        self._consume_value("(", "Expected '(' after function name")
        params = self._parse_parameters()
        self._consume_value(")", "Expected ')' after function parameters")
        self._consume_value(":", "Expected ':' after function signature")
        body = self._parse_block("Expected indented function body")
        return FunctionDef(
            location=self._location(token),
            name=name.name,
            params=[param.name for param in params],
            body=body,
        )

    def _parse_parameters(self) -> list[Identifier]:
        params: list[Identifier] = []
        if self._check_value(")"):
            return params

        while not self._check(TokenType.EOF):
            params.append(self._consume_identifier("Expected parameter name"))
            if not self._match_value(","):
                break
            if self._check_value(")"):
                break
        return params

    def _parse_if_stmt(self, token: Token) -> IfStmt:
        condition = self._parse_expression()
        self._consume_value(":", "Expected ':' after if condition")
        body = self._parse_block("Expected indented if body")
        else_body: list[Statement] = []

        if self._match_keyword("elif"):
            else_body = [self._parse_if_stmt(self._previous())]
        elif self._match_keyword("else"):
            self._consume_value(":", "Expected ':' after else")
            else_body = self._parse_block("Expected indented else body")

        return IfStmt(
            location=self._location(token),
            condition=condition,
            body=body,
            else_body=else_body,
        )

    def _parse_while_stmt(self, token: Token) -> WhileStmt:
        condition = self._parse_expression()
        self._consume_value(":", "Expected ':' after while condition")
        body = self._parse_block("Expected indented while body")
        return WhileStmt(location=self._location(token), condition=condition, body=body)

    def _parse_for_stmt(self, token: Token) -> ForStmt:
        target = self._consume_identifier("Expected loop target after 'for'")
        self._consume_keyword("in", "Expected 'in' after loop target")
        iterable = self._parse_expression()
        self._consume_value(":", "Expected ':' after for iterable")
        body = self._parse_block("Expected indented for body")
        return ForStmt(
            location=self._location(token),
            target=target,
            iterable=iterable,
            body=body,
        )

    def _parse_return_stmt(self, token: Token) -> ReturnStmt:
        if self._check(TokenType.NEWLINE, TokenType.DEDENT, TokenType.EOF):
            value = None
        else:
            value = self._parse_expression()
        self._match(TokenType.NEWLINE)
        return ReturnStmt(location=self._location(token), value=value)

    def _parse_simple_statement(self) -> Statement:
        expression = self._parse_expression()

        if self._match_value("="):
            if not isinstance(expression, Identifier):
                self._record_error("Assignment target must be an identifier", self._previous())
            value = self._parse_expression()
            self._match(TokenType.NEWLINE)
            target = expression if isinstance(expression, Identifier) else Identifier(
                location=expression.location,
                name="<invalid>",
            )
            return Assign(location=target.location, target=target, value=value)

        self._match(TokenType.NEWLINE)
        return ExprStmt(location=expression.location, expression=expression)

    def _parse_block(self, error_message: str) -> list[Statement]:
        self._consume(TokenType.NEWLINE, "Expected newline before block")
        if not self._match(TokenType.INDENT):
            token = self._peek()
            self._record_error(error_message, token)
            return [self._error_statement(error_message)]

        body: list[Statement] = []
        self._skip_newlines()
        while not self._check(TokenType.DEDENT, TokenType.EOF):
            statement = self._parse_statement()
            if statement is not None:
                body.append(statement)
            self._skip_newlines()

        self._consume(TokenType.DEDENT, "Expected dedent after block")
        return body

    def _parse_expression(self, min_precedence: int = 0) -> Expression:
        left = self._parse_primary()

        while True:
            operator = self._operator_value()
            precedence = self.PRECEDENCE.get(operator or "")
            if precedence is None or precedence < min_precedence:
                break

            self._advance()
            right = self._parse_expression(precedence + 1)
            left = BinaryExpr(
                location=left.location,
                left=left,
                operator=operator or "",
                right=right,
            )

        return left

    def _parse_primary(self) -> Expression:
        token = self._peek()

        if self._match(TokenType.NUMBER):
            return Literal(
                location=self._location(token),
                value=self._parse_number_value(token.value),
                raw=token.value,
            )
        if self._match(TokenType.STRING, TokenType.FSTRING):
            return Literal(location=self._location(token), value=token.value, raw=token.value)
        if self._match_keyword("True"):
            return Literal(location=self._location(token), value=True, raw=token.value)
        if self._match_keyword("False"):
            return Literal(location=self._location(token), value=False, raw=token.value)
        if self._match_keyword("None"):
            return Literal(location=self._location(token), value=None, raw=token.value)
        if self._match_value("("):
            expression = self._parse_expression()
            self._consume_value(")", "Expected ')' after expression")
            return expression
        if self._check(TokenType.IDENTIFIER) or self._check(TokenType.KEYWORD):
            return self._parse_identifier_or_call()

        self._record_error("Expected expression", token)
        self._advance()
        return Literal(location=self._location(token), value=None, raw=token.value)

    def _parse_identifier_or_call(self) -> Expression:
        first = self._advance()
        name_parts = [first.value]

        while self._match_value("."):
            part = self._consume_identifier("Expected identifier after '.'")
            name_parts.append(part.name)

        expression: Expression = Identifier(
            location=self._location(first),
            name=".".join(name_parts),
        )

        while self._match_value("("):
            args = self._parse_arguments()
            close_token = self._consume_value(")", "Expected ')' after call arguments")
            expression = CallExpr(
                location=expression.location,
                callee=expression,
                args=args,
            )
            if close_token.type == TokenType.EOF:
                break

        return expression

    def _parse_arguments(self) -> list[Expression]:
        args: list[Expression] = []
        if self._check_value(")"):
            return args

        while not self._check(TokenType.EOF):
            args.append(self._parse_expression())
            if not self._match_value(","):
                break
            if self._check_value(")"):
                break
        return args

    def _operator_value(self) -> str | None:
        if self._check(TokenType.OPERATOR):
            return self._peek().value
        if self._check(TokenType.KEYWORD) and self._peek().value in self.PRECEDENCE:
            return self._peek().value
        return None

    def _parse_number_value(self, raw: str) -> int | float:
        clean = raw.replace("_", "")
        try:
            if "." in clean or "e" in clean.lower():
                return float(clean)
            return int(clean, 0)
        except ValueError:
            self._record_error("Invalid numeric literal", self._previous())
            return 0

    def _consume_identifier(self, message: str) -> Identifier:
        if self._check(TokenType.IDENTIFIER) or self._check(TokenType.KEYWORD):
            token = self._advance()
            return Identifier(location=self._location(token), name=token.value)
        token = self._peek()
        self._record_error(message, token)
        return Identifier(location=self._location(token), name="<missing>")

    def _consume_keyword(self, value: str, message: str) -> Token:
        if self._match_keyword(value):
            return self._previous()
        return self._error_token(message)

    def _consume_value(self, value: str, message: str) -> Token:
        if self._match_value(value):
            return self._previous()
        return self._error_token(message)

    def _consume(self, token_type: TokenType, message: str) -> Token:
        if self._match(token_type):
            return self._previous()
        return self._error_token(message)

    def _error_statement(self, message: str) -> ParseErrorNode:
        token = self._peek()
        self._record_error(message, token)
        self._synchronize()
        return ParseErrorNode(
            location=self._location(token),
            message=message,
            token_value=token.value,
        )

    def _error_token(self, message: str) -> Token:
        token = self._peek()
        self._record_error(message, token)
        return token

    def _record_error(self, message: str, token: Token) -> None:
        self.errors.append(
            ParseError(
                message=message,
                line=token.line,
                column=token.column,
                token_value=token.value,
            )
        )

    def _synchronize(self) -> None:
        while not self._check(TokenType.EOF):
            if self._match(TokenType.NEWLINE):
                return
            if self._check(TokenType.DEDENT):
                return
            self._advance()

    def _skip_newlines(self) -> None:
        while self._match(TokenType.NEWLINE):
            pass

    def _match_keyword(self, value: str) -> bool:
        if self._check(TokenType.KEYWORD) and self._peek().value == value:
            self._advance()
            return True
        return False

    def _match_value(self, value: str) -> bool:
        if self._check_value(value):
            self._advance()
            return True
        return False

    def _check_value(self, value: str) -> bool:
        return not self._is_at_end() and self._peek().value == value

    def _match(self, *token_types: TokenType) -> bool:
        if self._check(*token_types):
            self._advance()
            return True
        return False

    def _check(self, *token_types: TokenType) -> bool:
        if self._is_at_end() and TokenType.EOF not in token_types:
            return False
        return self._peek().type in token_types

    def _advance(self) -> Token:
        if not self._is_at_end():
            self.current += 1
        return self._previous()

    def _is_at_end(self) -> bool:
        return self._peek().type == TokenType.EOF

    def _peek(self) -> Token:
        return self.tokens[self.current]

    def _previous(self) -> Token:
        return self.tokens[self.current - 1]

    def _location(self, token: Token) -> SourceLocation:
        return SourceLocation(line=token.line, column=token.column)


def parse(source: str) -> Program:
    return Parser.from_source(source).parse()


def parse_with_errors(source: str) -> tuple[Program, list[ParseError]]:
    parser = Parser.from_source(source)
    program = parser.parse()
    return program, parser.errors

