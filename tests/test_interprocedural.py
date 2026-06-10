"""Tests for Sprint 6: interprocedural analysis, reporter, hardener, metrics."""

from analyzer.cfg_builder import build_cfg
from analyzer.hardener import harden_source
from analyzer.interprocedural import analyze_module
from analyzer.ir_generator import generate_ir
from analyzer.metrics import ConfusionMatrix, evaluate
from analyzer.parser import parse
from analyzer.reporter import Reporter, TraceStep
from analyzer.taint_engine import analyze_cfg


# ------------------------------------------------------------------ helpers

def pipeline(source: str):
    program = parse(source)
    module = generate_ir(program)
    cfg = build_cfg(module.main.instructions)
    result = analyze_cfg(cfg)
    return module, cfg, result


# ================================================== Part A: interprocedural

def test_function_returning_source_has_returns_tainted():
    source = (
        "def get_user():\n"
        "    user = input()\n"
        "    return user\n"
    )
    module = generate_ir(parse(source))
    summaries = analyze_module(module)

    assert "get_user" in summaries
    s = summaries["get_user"]
    assert s.returns_tainted
    assert "input" in s.taint_sources


def test_function_with_request_source_has_returns_tainted():
    source = (
        "def fetch_id():\n"
        "    uid = request.args.get(\"id\")\n"
        "    return uid\n"
    )
    module = generate_ir(parse(source))
    summaries = analyze_module(module)
    assert summaries["fetch_id"].returns_tainted


def test_function_passing_through_param_has_taints_arguments():
    source = (
        "def wrap(value):\n"
        "    result = value\n"
        "    return result\n"
    )
    module = generate_ir(parse(source))
    summaries = analyze_module(module)
    assert summaries["wrap"].taints_arguments


def test_sanitizing_function_has_returns_sanitized():
    source = (
        "def clean(value):\n"
        "    safe = sanitize(value)\n"
        "    return safe\n"
    )
    module = generate_ir(parse(source))
    summaries = analyze_module(module)
    s = summaries["clean"]
    assert s.returns_sanitized
    assert not s.taints_arguments


def test_pure_function_has_no_taint_flags():
    source = (
        "def greet(name):\n"
        "    msg = \"Hello\"\n"
        "    return msg\n"
    )
    module = generate_ir(parse(source))
    summaries = analyze_module(module)
    s = summaries["greet"]
    assert not s.returns_tainted
    assert not s.returns_sanitized


# ================================================== Part B: reporter

def test_trace_has_source_flow_sink_steps():
    source = (
        "user = input()\n"
        "query = \"SELECT * FROM t WHERE id = \" + user\n"
        "cursor.execute(query)\n"
    )
    module, cfg, result = pipeline(source)
    assert result.is_vulnerable

    vuln = result.vulnerabilities[0]
    reporter = Reporter()
    trace = reporter.generate_trace(vuln, module.main.instructions)

    kinds = [step.kind for step in trace.steps]
    assert "SOURCE" in kinds
    assert "SINK" in kinds


def test_trace_source_step_identifies_taint_origin():
    source = "uid = request.args.get(\"id\")\ncursor.execute(uid)\n"
    module, cfg, result = pipeline(source)
    vuln = result.vulnerabilities[0]
    trace = Reporter().generate_trace(vuln, module.main.instructions)

    source_steps = [s for s in trace.steps if s.kind == "SOURCE"]
    assert source_steps
    assert any("request.args.get" in s.detail for s in source_steps)


def test_trace_sink_step_points_to_correct_function():
    source = "x = input()\ncursor.execute(x)\n"
    module, cfg, result = pipeline(source)
    vuln = result.vulnerabilities[0]
    trace = Reporter().generate_trace(vuln, module.main.instructions)

    sink_steps = [s for s in trace.steps if s.kind == "SINK"]
    assert sink_steps
    assert any("cursor.execute" in s.detail for s in sink_steps)


def test_trace_format_returns_string():
    source = "val = input()\ncursor.execute(val)\n"
    module, cfg, result = pipeline(source)
    vuln = result.vulnerabilities[0]
    trace = Reporter().generate_trace(vuln, module.main.instructions)
    text = trace.format()
    assert isinstance(text, str)
    assert "cursor.execute" in text


# ================================================== Part C: hardener

def test_hardener_converts_concat_to_parameterized():
    source = 'cursor.execute("SELECT * FROM t WHERE id = " + user_id)\n'
    result = harden_source(source)
    assert result.was_modified
    assert "?" in result.source
    assert "user_id" in result.source
    # Parameterized form: two arguments to execute()
    assert result.source.count(",") >= 1


def test_hardener_preserves_literal_query():
    source = 'cursor.execute("SELECT * FROM users")\n'
    result = harden_source(source)
    assert not result.was_modified
    assert result.source == source


def test_hardener_handles_engine_execute():
    source = 'engine.execute("DELETE FROM t WHERE name = " + name)\n'
    result = harden_source(source)
    assert result.was_modified
    assert "?" in result.source


def test_hardener_reports_modified_line_numbers():
    source = (
        'query = "SELECT 1"\n'
        'cursor.execute("SELECT * FROM t WHERE x = " + val)\n'
        'cursor.execute("SELECT 1")\n'
    )
    result = harden_source(source)
    assert result.changes_made == 1
    assert 2 in result.modified_lines


def test_hardener_multiline_source_only_touches_vulnerable_lines():
    source = (
        'a = 1\n'
        'cursor.execute("SELECT * FROM users WHERE id = " + uid)\n'
        'b = 2\n'
    )
    result = harden_source(source)
    lines = result.source.splitlines()
    assert lines[0] == "a = 1"
    assert lines[2] == "b = 2"
    assert "?" in lines[1]


# ================================================== Part D: metrics

def test_evaluate_perfect_detection():
    cm = evaluate(predicted={"a", "b"}, actual={"a", "b"})
    assert cm.tp == 2
    assert cm.fp == 0
    assert cm.fn == 0
    assert cm.precision == 1.0
    assert cm.recall == 1.0
    assert cm.f1_score == 1.0


def test_evaluate_false_positives_lower_precision():
    cm = evaluate(predicted={"a", "b", "c"}, actual={"a", "b"}, universe={"a", "b", "c"})
    assert cm.fp == 1
    assert cm.precision < 1.0
    assert cm.recall == 1.0


def test_evaluate_false_negatives_lower_recall():
    cm = evaluate(predicted={"a"}, actual={"a", "b"}, universe={"a", "b"})
    assert cm.fn == 1
    assert cm.recall < 1.0
    assert cm.precision == 1.0


def test_evaluate_zero_division_returns_zero():
    cm = ConfusionMatrix(tp=0, fp=0, tn=5, fn=0)
    assert cm.precision == 0.0
    assert cm.recall == 0.0
    assert cm.f1_score == 0.0


def test_f1_harmonic_mean_of_precision_and_recall():
    cm = evaluate(predicted={"a", "b", "c"}, actual={"a", "b", "d"}, universe={"a", "b", "c", "d"})
    assert cm.tp == 2
    assert cm.fp == 1
    assert cm.fn == 1
    expected_f1 = 2 * cm.precision * cm.recall / (cm.precision + cm.recall)
    assert abs(cm.f1_score - expected_f1) < 1e-9


def test_confusion_matrix_str_contains_all_fields():
    cm = ConfusionMatrix(tp=3, fp=1, tn=5, fn=2)
    text = str(cm)
    assert "TP=3" in text
    assert "FP=1" in text
    assert "Precision" in text
    assert "Recall" in text
    assert "F1" in text
