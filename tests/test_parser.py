from analyzer.ast_nodes import (
    Assign,
    BinaryExpr,
    CallExpr,
    CollectionExpr,
    ExprStmt,
    ForStmt,
    FunctionDef,
    Identifier,
    IfStmt,
    ImportStmt,
    Literal,
    ReturnStmt,
    WhileStmt,
)
from analyzer.ast_visualizer import visualize
from contextlib import redirect_stdout
from demos.demo_secureflow import main as demo_main
from io import StringIO
from analyzer.parser import Parser, parse, parse_with_errors


def test_parse_function_with_assignment_and_return():
    program = parse(
        """def get_user():
    user = request.args.get("user")
    return user
"""
    )

    function = program.body[0]

    assert isinstance(function, FunctionDef)
    assert function.name == "get_user"
    assert function.params == []
    assert isinstance(function.body[0], Assign)
    assert function.body[0].target.name == "user"
    assert isinstance(function.body[0].value, CallExpr)
    assert isinstance(function.body[0].value.callee, Identifier)
    assert function.body[0].value.callee.name == "request.args.get"
    assert isinstance(function.body[1], ReturnStmt)


def test_parse_if_while_for_blocks():
    program = parse(
        """if user:
    total = 0
    while total < 3:
        total = total + 1
else:
    for item in users:
        total = item
"""
    )

    if_stmt = program.body[0]

    assert isinstance(if_stmt, IfStmt)
    assert isinstance(if_stmt.body[0], Assign)
    assert isinstance(if_stmt.body[1], WhileStmt)
    assert isinstance(if_stmt.body[1].condition, BinaryExpr)
    assert isinstance(if_stmt.else_body[0], ForStmt)
    assert if_stmt.else_body[0].target.name == "item"


def test_parse_binary_expression_precedence():
    program = parse("result = a + b * 3\n")
    assignment = program.body[0]

    assert isinstance(assignment, Assign)
    assert isinstance(assignment.value, BinaryExpr)
    assert assignment.value.operator == "+"
    assert isinstance(assignment.value.right, BinaryExpr)
    assert assignment.value.right.operator == "*"


def test_parse_call_statement_for_future_sink_detection():
    program = parse('cursor.execute("SELECT " + user)\n')
    statement = program.body[0]

    assert isinstance(statement, ExprStmt)
    assert isinstance(statement.expression, CallExpr)
    assert isinstance(statement.expression.callee, Identifier)
    assert statement.expression.callee.name == "cursor.execute"
    assert isinstance(statement.expression.args[0], BinaryExpr)


def test_parse_parameter_tuple_without_errors():
    parser = Parser.from_source(
        'cursor.execute("SELECT * FROM users WHERE id = ?", (user,))\n'
    )
    program = parser.parse()

    assert not parser.errors
    statement = program.body[0]
    assert isinstance(statement, ExprStmt)
    call = statement.expression
    assert isinstance(call, CallExpr)
    assert len(call.args) == 2
    assert isinstance(call.args[1], CollectionExpr)
    assert call.args[1].kind == "tuple"
    assert len(call.args[1].elements) == 1


def test_parse_flask_import_alias_and_decorator():
    parser = Parser.from_source(
        'from flask import request as req\n'
        '\n'
        '@app.route("/users", methods=["POST"])\n'
        'def users():\n'
        '    value = req.form.get("name")\n'
    )
    program = parser.parse()

    assert not parser.errors
    assert isinstance(program.body[0], ImportStmt)
    assert program.body[0].aliases["req"] == "flask.request"
    assert isinstance(program.body[1], FunctionDef)
    assert program.body[1].name == "users"


def test_parse_dict_argument_for_sqlalchemy_parameters():
    parser = Parser.from_source(
        'db.session.execute(stmt, {"name": user})\n'
    )
    program = parser.parse()

    assert not parser.errors
    statement = program.body[0]
    assert isinstance(statement, ExprStmt)
    call = statement.expression
    assert isinstance(call, CallExpr)
    assert isinstance(call.args[1], CollectionExpr)
    assert call.args[1].kind == "dict"


def test_parse_literals_and_positions():
    program = parse("enabled = True\nlimit = 10\nname = 'admin'\n")

    enabled = program.body[0]
    limit = program.body[1]
    name = program.body[2]

    assert isinstance(enabled, Assign)
    assert isinstance(enabled.value, Literal)
    assert enabled.value.value is True
    assert isinstance(limit.value, Literal)
    assert limit.value.value == 10
    assert name.location.line == 3
    assert name.target.column == 1


def test_parser_reports_errors_and_recovers():
    program, errors = parse_with_errors(
        """def broken()
    value = 1
next_value = 2
"""
    )

    assert errors
    assert any("Expected ':'" in error.message for error in errors)
    assert any(isinstance(statement, Assign) and statement.target.name == "next_value" for statement in program.body)


def test_visualizer_explains_tree_shape():
    program = parse(
        """def get_user():
    return request.form.get("user")
"""
    )

    tree = visualize(program)

    assert "Program @1:1" in tree
    assert "FunctionDef name=get_user" in tree
    assert "ReturnStmt" in tree
    assert "CallExpr" in tree
    assert "Identifier name=request.form.get" in tree


def test_parser_class_keeps_errors_for_professor_demo():
    parser = Parser.from_source("if user\n    value = 1\n")
    program = parser.parse()

    assert program.body
    assert parser.errors
    assert parser.errors[0].line == 1



def test_demo_script_runs_end_to_end():
    output_buffer = StringIO()

    with redirect_stdout(output_buffer):
        demo_main()

    output = output_buffer.getvalue()
    assert "Lexer: codigo convertido a tokens" in output
    assert "Parser: tokens convertidos a AST propio" in output
    assert "request.args.get" in output
    assert "cursor.execute" in output
