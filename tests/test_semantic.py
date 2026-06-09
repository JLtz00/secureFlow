from analyzer.semantic import analyze_source


def symbol_by_name(result, name):
    matches = [symbol for symbol in result.symbols.all_symbols() if symbol.name == name]
    assert matches, f"Expected symbol {name!r}"
    return matches[-1]


def test_builds_global_and_function_scopes():
    result = analyze_source(
        """def get_user():
    user = request.args.get("user")
    return user

query = "SELECT " + get_user()
"""
    )

    function = symbol_by_name(result, "get_user")
    user = symbol_by_name(result, "user")
    query = symbol_by_name(result, "query")

    assert function.kind == "function"
    assert function.scope_name == "global"
    assert user.scope_name == "get_user"
    assert query.scope_name == "global"


def test_marks_request_args_get_assignment_as_tainted():
    result = analyze_source('user = request.args.get("user")\n')
    user = symbol_by_name(result, "user")

    assert user.is_tainted
    assert user.type_name == "str"
    assert user.taint_sources == ["request.args.get"]


def test_marks_request_form_get_and_input_as_sources():
    result = analyze_source(
        """email = request.form.get("email")
password = input()
"""
    )

    assert symbol_by_name(result, "email").taint_sources == ["request.form.get"]
    assert symbol_by_name(result, "password").taint_sources == ["input"]


def test_propagates_taint_through_identifier_and_binary_expression():
    result = analyze_source(
        """user = input()
query = "SELECT " + user
copy = query
"""
    )

    query = symbol_by_name(result, "query")
    copy = symbol_by_name(result, "copy")

    assert query.is_tainted
    assert query.type_name == "str"
    assert copy.is_tainted
    assert copy.taint_sources == ["input"]


def test_sanitizer_clears_taint_for_initial_preprocessing():
    result = analyze_source(
        """user = input()
safe_user = sanitize(user)
"""
    )

    assert symbol_by_name(result, "user").is_tainted
    assert not symbol_by_name(result, "safe_user").is_tainted


def test_reports_unresolved_names():
    result = analyze_source("query = prefix + user\n")

    names = {issue.name for issue in result.issues}

    assert "prefix" in names
    assert "user" in names


def test_nested_block_scope_symbols():
    result = analyze_source(
        """user = input()
if user:
    query = user
"""
    )

    query = symbol_by_name(result, "query")

    assert query.scope_name.startswith("if@")
    assert query.is_tainted
