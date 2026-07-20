from analyzer.lexer import Lexer, TokenType, tokenize


def strip_layout(tokens):
    return [
        token
        for token in tokens
        if token.type not in {TokenType.NEWLINE, TokenType.INDENT, TokenType.DEDENT, TokenType.EOF}
    ]


def test_variables_and_assignment_tokens():
    tokens = strip_layout(tokenize("user = request.args.get('user')\n"))

    assert [(token.type, token.value) for token in tokens] == [
        (TokenType.IDENTIFIER, "user"),
        (TokenType.OPERATOR, "="),
        (TokenType.IDENTIFIER, "request"),
        (TokenType.OPERATOR, "."),
        (TokenType.IDENTIFIER, "args"),
        (TokenType.OPERATOR, "."),
        (TokenType.IDENTIFIER, "get"),
        (TokenType.DELIMITER, "("),
        (TokenType.STRING, "'user'"),
        (TokenType.DELIMITER, ")"),
    ]


def test_functions_and_nested_blocks_emit_indent_dedent():
    source = """def handler():
    if user:
        return user
    return None
"""

    tokens = tokenize(source)

    assert [token.value for token in tokens if token.type == TokenType.KEYWORD] == [
        "def",
        "if",
        "return",
        "return",
        "None",
    ]
    assert [token.type for token in tokens].count(TokenType.INDENT) == 2
    assert [token.type for token in tokens].count(TokenType.DEDENT) == 2


def test_multiline_string_tracks_position_and_value():
    source = 'query = """SELECT *\nFROM users\nWHERE name = ?"""\n'

    tokens = tokenize(source)
    string_token = next(token for token in tokens if token.type == TokenType.STRING)

    assert string_token.value == '"""SELECT *\nFROM users\nWHERE name = ?"""'
    assert string_token.line == 1
    assert string_token.column == 9
    assert tokens[-1].type == TokenType.EOF
    assert tokens[-1].line == 4


def test_fstrings_are_distinct_from_regular_strings():
    tokens = strip_layout(tokenize('message = f"hello {user}"\n'))

    assert any(token.type == TokenType.FSTRING for token in tokens)
    assert not any(token.type == TokenType.ERROR for token in tokens)


def test_comments_are_removed():
    tokens = tokenize("# ignored\nuser = 1  # also ignored\n")

    assert "#" not in [token.value for token in tokens]
    assert [token.value for token in strip_layout(tokens)] == ["user", "=", "1"]


def test_malformed_tokens_recover_and_continue():
    tokens = strip_layout(tokenize("user = $\nnext_value = 2\n"))

    error = next(token for token in tokens if token.type == TokenType.ERROR)
    assert error.value == "$"
    assert error.line == 1
    assert error.column == 8
    assert any(token.value == "next_value" for token in tokens)


def test_unterminated_single_line_string_reports_error():
    tokens = strip_layout(tokenize("name = 'lorenzo\nvalue = 3\n"))

    error = next(token for token in tokens if token.type == TokenType.ERROR)
    assert "unterminated string" in error.value
    assert any(token.value == "value" for token in tokens)


def test_parenthesized_newlines_do_not_create_layout_tokens():
    source = """query = (
    "SELECT"
    + user
)
"""

    tokens = tokenize(source)

    assert [token.type for token in tokens].count(TokenType.INDENT) == 0
    assert [token.type for token in tokens].count(TokenType.DEDENT) == 0
    assert [token.type for token in tokens].count(TokenType.NEWLINE) == 1


def test_token_position_tracking():
    lexer = Lexer()
    tokens = lexer.tokenize("    user = 42\n")

    user = next(token for token in tokens if token.value == "user")
    number = next(token for token in tokens if token.value == "42")

    assert user.line == 1
    assert user.column == 5
    assert number.line == 1
    assert number.column == 12
