"""Lexical analyzer for SecureFlow's Python subset."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Iterable


class TokenType(str, Enum):
    IDENTIFIER = "IDENTIFIER"
    KEYWORD = "KEYWORD"
    NUMBER = "NUMBER"
    STRING = "STRING"
    FSTRING = "FSTRING"
    OPERATOR = "OPERATOR"
    DELIMITER = "DELIMITER"
    INDENT = "INDENT"
    DEDENT = "DEDENT"
    NEWLINE = "NEWLINE"
    ERROR = "ERROR"
    EOF = "EOF"


@dataclass(frozen=True)
class Token:
    type: TokenType
    value: str
    line: int
    column: int


class Lexer:
    """Regex-based scanner with Python-style indentation tokens."""

    KEYWORDS = {
        "and",
        "as",
        "assert",
        "break",
        "class",
        "continue",
        "def",
        "del",
        "elif",
        "else",
        "except",
        "False",
        "finally",
        "for",
        "from",
        "global",
        "if",
        "import",
        "in",
        "is",
        "lambda",
        "None",
        "nonlocal",
        "not",
        "or",
        "pass",
        "raise",
        "return",
        "True",
        "try",
        "while",
        "with",
        "yield",
    }

    OPERATORS = (
        "==",
        "!=",
        "<=",
        ">=",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "**",
        "//",
        "->",
        ":=",
        "=",
        "+",
        "-",
        "*",
        "/",
        "%",
        "<",
        ">",
        ".",
    )
    DELIMITERS = {"(", ")", "[", "]", "{", "}", ",", ":", ";"}
    OPENING_DELIMITERS = {"(", "[", "{"}
    CLOSING_DELIMITERS = {")", "]", "}"}

    _IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    _NUMBER_RE = re.compile(
        r"""
        (?:
            0[bB][01_]+
            |0[oO][0-7_]+
            |0[xX][0-9A-Fa-f_]+
            |\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?
            |\.\d[\d_]*(?:[eE][+-]?\d[\d_]*)?
        )
        """,
        re.VERBOSE,
    )
    _STRING_PREFIX_RE = re.compile(r"(?i)(?:r|u|b|br|rb|f|fr|rf)")

    def __init__(self, tab_width: int = 4) -> None:
        self.tab_width = tab_width

    def tokenize(self, source: str) -> list[Token]:
        tokens: list[Token] = []
        indent_stack = [0]
        index = 0
        line = 1
        column = 1
        at_line_start = True
        bracket_depth = 0

        while index < len(source):
            char = source[index]

            if at_line_start and bracket_depth == 0:
                index, column, indentation = self._consume_indentation(
                    source, index, column
                )
                if index >= len(source):
                    break
                char = source[index]
                if char in "\r\n":
                    index, line, column = self._consume_newline(source, index, line)
                    at_line_start = True
                    continue
                if char == "#":
                    index, line, column = self._skip_comment_line(source, index, line)
                    at_line_start = True
                    continue

                if indentation > indent_stack[-1]:
                    indent_stack.append(indentation)
                    tokens.append(Token(TokenType.INDENT, "", line, 1))
                elif indentation < indent_stack[-1]:
                    while len(indent_stack) > 1 and indentation < indent_stack[-1]:
                        indent_stack.pop()
                        tokens.append(Token(TokenType.DEDENT, "", line, 1))
                    if indentation != indent_stack[-1]:
                        tokens.append(
                            Token(
                                TokenType.ERROR,
                                f"inconsistent indentation ({indentation})",
                                line,
                                1,
                            )
                        )
                at_line_start = False

            if char in " \t\f":
                index, column = self._consume_inline_whitespace(source, index, column)
                continue

            if char == "#":
                index, column = self._skip_comment(source, index, column)
                continue

            if char in "\r\n":
                if bracket_depth == 0:
                    tokens.append(Token(TokenType.NEWLINE, "\n", line, column))
                index, line, column = self._consume_newline(source, index, line)
                at_line_start = True
                continue

            string_token = self._scan_string(source, index, line, column)
            if string_token is not None:
                token, index, line, column = string_token
                tokens.append(token)
                at_line_start = False
                continue

            match = self._NUMBER_RE.match(source, index)
            if match is not None:
                value = match.group(0)
                tokens.append(Token(TokenType.NUMBER, value, line, column))
                index += len(value)
                column += len(value)
                at_line_start = False
                continue

            match = self._IDENTIFIER_RE.match(source, index)
            if match is not None:
                value = match.group(0)
                token_type = TokenType.KEYWORD if value in self.KEYWORDS else TokenType.IDENTIFIER
                tokens.append(Token(token_type, value, line, column))
                index += len(value)
                column += len(value)
                at_line_start = False
                continue

            if char in self.DELIMITERS:
                tokens.append(Token(TokenType.DELIMITER, char, line, column))
                if char in self.OPENING_DELIMITERS:
                    bracket_depth += 1
                elif char in self.CLOSING_DELIMITERS and bracket_depth > 0:
                    bracket_depth -= 1
                index += 1
                column += 1
                at_line_start = False
                continue

            operator = self._match_operator(source, index)
            if operator is not None:
                tokens.append(Token(TokenType.OPERATOR, operator, line, column))
                index += len(operator)
                column += len(operator)
                at_line_start = False
                continue

            tokens.append(Token(TokenType.ERROR, char, line, column))
            index += 1
            column += 1
            at_line_start = False

        while len(indent_stack) > 1:
            indent_stack.pop()
            tokens.append(Token(TokenType.DEDENT, "", line, 1))

        tokens.append(Token(TokenType.EOF, "", line, column))
        return tokens

    def token_values(self, source: str) -> list[str]:
        return [token.value for token in self.tokenize(source)]

    def _consume_indentation(
        self, source: str, index: int, column: int
    ) -> tuple[int, int, int]:
        indentation = 0
        while index < len(source) and source[index] in " \t\f":
            if source[index] == "\t":
                indentation += self.tab_width - (indentation % self.tab_width)
                column += self.tab_width
            elif source[index] == "\f":
                indentation = 0
                column = 1
            else:
                indentation += 1
                column += 1
            index += 1
        return index, column, indentation

    def _consume_inline_whitespace(
        self, source: str, index: int, column: int
    ) -> tuple[int, int]:
        while index < len(source) and source[index] in " \t\f":
            column += self.tab_width if source[index] == "\t" else 1
            index += 1
        return index, column

    def _consume_newline(
        self, source: str, index: int, line: int
    ) -> tuple[int, int, int]:
        if source.startswith("\r\n", index):
            index += 2
        else:
            index += 1
        return index, line + 1, 1

    def _skip_comment(self, source: str, index: int, column: int) -> tuple[int, int]:
        while index < len(source) and source[index] not in "\r\n":
            index += 1
            column += 1
        return index, column

    def _skip_comment_line(
        self, source: str, index: int, line: int
    ) -> tuple[int, int, int]:
        while index < len(source) and source[index] not in "\r\n":
            index += 1
        if index < len(source):
            return self._consume_newline(source, index, line)
        return index, line, 1

    def _scan_string(
        self, source: str, index: int, line: int, column: int
    ) -> tuple[Token, int, int, int] | None:
        prefix = ""
        quote_index = index
        if source[index] not in "'\"":
            prefix_match = self._STRING_PREFIX_RE.match(source, index)
            if prefix_match is None:
                return None
            prefix = prefix_match.group(0)
            quote_index = index + len(prefix)
            if quote_index >= len(source) or source[quote_index] not in "'\"":
                return None

        quote = source[quote_index]
        delimiter = quote * 3 if source.startswith(quote * 3, quote_index) else quote
        cursor = quote_index + len(delimiter)
        current_line = line
        current_column = column + len(prefix) + len(delimiter)
        escaped = False

        while cursor < len(source):
            if source.startswith(delimiter, cursor) and (len(delimiter) == 3 or not escaped):
                cursor += len(delimiter)
                current_column += len(delimiter)
                value = source[index:cursor]
                token_type = TokenType.FSTRING if "f" in prefix.lower() else TokenType.STRING
                return Token(token_type, value, line, column), cursor, current_line, current_column

            char = source[cursor]
            if char in "\r\n":
                if len(delimiter) == 1:
                    value = source[index:cursor]
                    return (
                        Token(TokenType.ERROR, f"unterminated string {value!r}", line, column),
                        cursor,
                        current_line,
                        current_column,
                    )
                cursor, current_line, current_column = self._consume_newline(
                    source, cursor, current_line
                )
                escaped = False
                continue

            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
            cursor += 1
            current_column += 1

        value = source[index:cursor]
        return (
            Token(TokenType.ERROR, f"unterminated string {value!r}", line, column),
            cursor,
            current_line,
            current_column,
        )

    def _match_operator(self, source: str, index: int) -> str | None:
        for operator in self.OPERATORS:
            if source.startswith(operator, index):
                return operator
        return None


def tokenize(source: str) -> list[Token]:
    return Lexer().tokenize(source)


def iter_tokens(source: str) -> Iterable[Token]:
    return iter(tokenize(source))
