"""Tests for Sprint 5: forward dataflow taint engine (Worklist algorithm)."""

from analyzer.cfg_builder import build_cfg
from analyzer.framework_profiles import get_profile
from analyzer.interprocedural import analyze_module
from analyzer.ir_generator import generate_ir
from analyzer.parser import parse
from analyzer.taint_engine import TaintResult, analyze_cfg


# ------------------------------------------------------------------ helpers

def run(source: str) -> TaintResult:
    """Full pipeline: source code → IR → CFG → taint analysis."""
    program = parse(source)
    module = generate_ir(program)
    cfg = build_cfg(module.main.instructions)
    return analyze_cfg(cfg)


def run_interprocedural(source: str) -> TaintResult:
    """Full pipeline with function summaries enabled."""
    program = parse(source)
    module = generate_ir(program)
    cfg = build_cfg(module.main.instructions)
    return analyze_cfg(cfg, summaries=analyze_module(module))


def run_flask(source: str) -> TaintResult:
    """Full pipeline with the Flask security profile enabled."""
    profile = get_profile("flask")
    program = parse(source)
    module = generate_ir(program)
    summaries = analyze_module(module, profile=profile)
    combined = TaintResult()
    for function in module.all_functions():
        cfg = build_cfg(function.instructions, name=function.name)
        result = analyze_cfg(cfg, summaries=summaries, profile=profile)
        combined.vulnerabilities.extend(result.vulnerabilities)
        combined.block_out.update(result.block_out)
    return combined


def sink_names(result: TaintResult) -> list[str]:
    return [v.sink for v in result.vulnerabilities]


def taint_sources_for(result: TaintResult, sink: str) -> frozenset[str]:
    for v in result.vulnerabilities:
        if v.sink == sink:
            return v.taint_sources
    return frozenset()


# -------------------------------------------------------- source detection

def test_input_source_taints_variable():
    result = run('user = input()\n')
    # No sink, so no vulnerability; but the block_out should hold taint state
    assert not result.is_vulnerable
    tainted_vars = {
        var for block_state in result.block_out.values() for var in block_state
    }
    # The temp holding input() return and 'user' should be tainted
    assert tainted_vars, "Expected at least one tainted variable after input()"


def test_request_args_get_taints_variable():
    result = run('uid = request.args.get("id")\n')
    assert not result.is_vulnerable
    tainted = {v for s in result.block_out.values() for v in s}
    assert tainted


# ------------------------------------------ sink detection (vulnerabilities)

def test_direct_taint_to_sink_is_detected():
    result = run(
        'user = input()\n'
        'cursor.execute(user)\n'
    )
    assert result.is_vulnerable
    assert "cursor.execute" in sink_names(result)


def test_engine_execute_sink_is_detected():
    result = run(
        'uid = request.args.get("id")\n'
        'engine.execute(uid)\n'
    )
    assert result.is_vulnerable
    assert "engine.execute" in sink_names(result)
    assert "request.args.get" in taint_sources_for(result, "engine.execute")


# ----------------------------------------- propagation through assignments

def test_taint_propagates_through_assignment_chain():
    result = run(
        'user = input()\n'
        'alias = user\n'
        'cursor.execute(alias)\n'
    )
    assert result.is_vulnerable
    assert "input" in taint_sources_for(result, "cursor.execute")


# ------------------------------------------- propagation through binary ops

def test_taint_propagates_through_string_concatenation():
    result = run(
        'user = request.form.get("name")\n'
        'query = "SELECT * FROM t WHERE name = \'" + user\n'
        'cursor.execute(query)\n'
    )
    assert result.is_vulnerable
    sources = taint_sources_for(result, "cursor.execute")
    assert "request.form.get" in sources


# ---------------------------------------------- sanitizer clears taint

def test_sanitizer_prevents_vulnerability():
    result = run(
        'user = input()\n'
        'safe = sanitize(user)\n'
        'cursor.execute(safe)\n'
    )
    assert not result.is_vulnerable


def test_escape_sanitizer_prevents_vulnerability():
    result = run(
        'uid = request.args.get("id")\n'
        'clean = escape(uid)\n'
        'cursor.execute(clean)\n'
    )
    assert not result.is_vulnerable


# --------------------------------------- propagation through if branches

def test_taint_propagates_through_if_branch():
    result = run(
        'user = input()\n'
        'if user:\n'
        '    query = user\n'
        'cursor.execute(query)\n'
    )
    assert result.is_vulnerable


def test_tainted_and_clean_branch_merge_is_still_tainted():
    result = run(
        'user = input()\n'
        'if user:\n'
        '    q = user\n'
        'else:\n'
        '    q = "SELECT 1"\n'
        'cursor.execute(q)\n'
    )
    # After join, q could be tainted (conservative union)
    assert result.is_vulnerable


# --------------------------------------- propagation through while loops

def test_taint_propagates_through_while_loop():
    result = run(
        'user = input()\n'
        'count = 0\n'
        'while count < 3:\n'
        '    query = user\n'
        '    count = count + 1\n'
        'cursor.execute(query)\n'
    )
    assert result.is_vulnerable


# ------------------------------------------- clean paths (no vulnerability)

def test_literal_query_is_not_vulnerable():
    result = run(
        'query = "SELECT * FROM users"\n'
        'cursor.execute(query)\n'
    )
    assert not result.is_vulnerable


def test_parameterized_query_with_tainted_parameter_is_not_vulnerable():
    result = run(
        'user = request.form.get("field")\n'
        'cursor.execute("SELECT * FROM users WHERE id = ?", (user,))\n'
    )
    assert not result.is_vulnerable


def test_tainted_query_template_is_vulnerable_even_with_parameters():
    result = run(
        'table = input()\n'
        'query = "SELECT * FROM " + table + " WHERE id = ?"\n'
        'cursor.execute(query, (user,))\n'
    )
    assert result.is_vulnerable


def test_interprocedural_source_return_reaches_sink():
    result = run_interprocedural(
        'def get_param():\n'
        '    return request.form.get("field")\n'
        '\n'
        'user = get_param()\n'
        'cursor.execute("SELECT * FROM users WHERE id = " + user)\n'
    )
    assert result.is_vulnerable


def test_interprocedural_sanitizer_return_cleans_value():
    result = run_interprocedural(
        'def clean(value):\n'
        '    return sanitize(value)\n'
        '\n'
        'user = input()\n'
        'safe = clean(user)\n'
        'cursor.execute(safe)\n'
    )
    assert not result.is_vulnerable


def test_flask_alias_source_reaches_db_session_execute():
    result = run_flask(
        'from flask import request as req\n'
        '@app.route("/login", methods=["POST"])\n'
        'def login():\n'
        '    username = req.form.get("username")\n'
        '    query = "SELECT * FROM users WHERE username = " + username\n'
        '    db.session.execute(query)\n'
    )
    assert result.is_vulnerable


def test_flask_fstring_query_is_vulnerable():
    result = run_flask(
        'from flask import request\n'
        '@app.route("/orders")\n'
        'def orders():\n'
        '    order_id = request.values.get("id")\n'
        '    query = f"SELECT * FROM orders WHERE id = {order_id}"\n'
        '    cursor.execute(query)\n'
    )
    assert result.is_vulnerable


def test_flask_sqlalchemy_text_with_bind_params_is_safe():
    result = run_flask(
        'from flask import request\n'
        'from sqlalchemy import text\n'
        '@app.route("/users")\n'
        'def users():\n'
        '    user = request.args.get("user")\n'
        '    stmt = text("SELECT * FROM users WHERE name = :name")\n'
        '    db.session.execute(stmt, {"name": user})\n'
    )
    assert not result.is_vulnerable


def test_is_vulnerable_property():
    clean = run('cursor.execute("SELECT 1")\n')
    dirty = run('x = input()\ncursor.execute(x)\n')
    assert not clean.is_vulnerable
    assert dirty.is_vulnerable
