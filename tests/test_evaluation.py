"""Tests for Sprint 7: dataset generator, benchmark runner, performance
evaluator, updated metrics, and visualizer."""

import json
import tempfile
from pathlib import Path

from analyzer.metrics import ConfusionMatrix, evaluate


# ============================================= Updated metrics (Part C)

def test_accuracy_all_correct():
    cm = ConfusionMatrix(tp=8, fp=0, tn=2, fn=0)
    assert cm.accuracy == 1.0


def test_accuracy_mixed():
    cm = ConfusionMatrix(tp=3, fp=1, tn=4, fn=2)
    assert abs(cm.accuracy - (3 + 4) / 10) < 1e-9


def test_fpr_no_negatives_returns_zero():
    cm = ConfusionMatrix(tp=5, fp=0, tn=0, fn=0)
    assert cm.fpr == 0.0


def test_fpr_computed_correctly():
    cm = ConfusionMatrix(tp=0, fp=2, tn=8, fn=0)
    assert abs(cm.fpr - 2 / 10) < 1e-9


def test_fnr_no_positives_returns_zero():
    cm = ConfusionMatrix(tp=0, fp=0, tn=5, fn=0)
    assert cm.fnr == 0.0


def test_fnr_computed_correctly():
    cm = ConfusionMatrix(tp=4, fp=0, tn=0, fn=1)
    assert abs(cm.fnr - 1 / 5) < 1e-9


def test_str_contains_new_metrics():
    cm = ConfusionMatrix(tp=3, fp=1, tn=5, fn=1)
    s = str(cm)
    assert "Accuracy" in s
    assert "FPR" in s
    assert "FNR" in s


# ============================================= Dataset generator (Part A)

def test_dataset_generator_creates_expected_file_count():
    from tools.dataset_generator import DatasetGenerator
    with tempfile.TemporaryDirectory() as tmp:
        gen = DatasetGenerator(output_dir=tmp + "/dataset")
        import os
        os.chdir(tmp)
        entries = gen.generate(210)
        assert len(entries) == 210


def test_dataset_generator_labels_are_valid():
    from tools.dataset_generator import DatasetGenerator
    with tempfile.TemporaryDirectory() as tmp:
        import os
        os.chdir(tmp)
        gen = DatasetGenerator(output_dir=tmp + "/dataset")
        entries = gen.generate(50)
        for e in entries:
            assert e.label in ("VULNERABLE", "SAFE")
            assert e.category in ("A", "B", "C", "D", "E")


def test_dataset_generator_writes_metadata_json():
    from tools.dataset_generator import DatasetGenerator
    with tempfile.TemporaryDirectory() as tmp:
        import os
        os.chdir(tmp)
        gen = DatasetGenerator(output_dir=tmp + "/dataset")
        gen.generate(10)
        meta = json.loads(Path(tmp + "/dataset_metadata.json").read_text())
        assert len(meta) == 10
        assert all("file" in e and "label" in e for e in meta)


def test_dataset_has_both_vulnerable_and_safe():
    from tools.dataset_generator import DatasetGenerator
    with tempfile.TemporaryDirectory() as tmp:
        import os
        os.chdir(tmp)
        gen = DatasetGenerator(output_dir=tmp + "/dataset")
        entries = gen.generate(50)
        labels = {e.label for e in entries}
        assert "VULNERABLE" in labels
        assert "SAFE" in labels


def test_generated_programs_parse_without_error():
    from tools.dataset_generator import DatasetGenerator
    from analyzer.parser import parse
    with tempfile.TemporaryDirectory() as tmp:
        import os
        os.chdir(tmp)
        gen = DatasetGenerator(output_dir=tmp + "/dataset")
        entries = gen.generate(20)
        dataset_dir = Path(tmp + "/dataset")
        for e in entries:
            source = (dataset_dir / e.file).read_text()
            program = parse(source)
            assert program is not None


# ============================================= Benchmark runner (Part B)

def _setup_benchmark(tmp: str, count: int = 20):
    """Helper: generate dataset and metadata in tmp dir."""
    from tools.dataset_generator import DatasetGenerator
    import os
    os.chdir(tmp)
    gen = DatasetGenerator(output_dir=tmp + "/dataset")
    gen.generate(count)
    return tmp + "/dataset", tmp + "/dataset_metadata.json"


def test_benchmark_runner_returns_only_secureflow_records():
    from tools.benchmark_runner import BenchmarkRunner
    with tempfile.TemporaryDirectory() as tmp:
        ds_dir, meta_file = _setup_benchmark(tmp, 10)
        runner = BenchmarkRunner(dataset_dir=ds_dir, metadata_file=meta_file)
        records = runner.run()
        tools = {r.tool for r in records}
        assert {"SecureFlow"} == tools


def test_benchmark_runner_predictions_are_valid_labels():
    from tools.benchmark_runner import BenchmarkRunner
    with tempfile.TemporaryDirectory() as tmp:
        ds_dir, meta_file = _setup_benchmark(tmp, 10)
        runner = BenchmarkRunner(dataset_dir=ds_dir, metadata_file=meta_file)
        records = runner.run()
        for r in records:
            assert r.prediction in ("VULNERABLE", "SAFE")


def test_benchmark_runner_secureflow_detects_direct_sqli():
    from tools.benchmark_runner import BenchmarkRunner
    with tempfile.TemporaryDirectory() as tmp:
        ds_dir, meta_file = _setup_benchmark(tmp, 50)
        runner = BenchmarkRunner(dataset_dir=ds_dir, metadata_file=meta_file)
        records = runner.run()
        meta = json.loads(Path(meta_file).read_text())
        cat_a = {e["file"] for e in meta if e["category"] == "A"}
        sf_on_a = [r for r in records if r.tool == "SecureFlow" and r.file in cat_a]
        detected = sum(1 for r in sf_on_a if r.prediction == "VULNERABLE")
        assert detected > 0, "SecureFlow should detect some direct SQLi"


def test_flask_dataset_secureflow_profile_is_perfect_on_seed_cases():
    from tools.benchmark_runner import BenchmarkRunner
    from tools.flask_dataset_generator import FlaskDatasetGenerator
    with tempfile.TemporaryDirectory() as tmp:
        dataset_dir = Path(tmp) / "flask_dataset"
        metadata_file = Path(tmp) / "flask_dataset_metadata.json"
        FlaskDatasetGenerator(dataset_dir, metadata_file).generate()
        runner = BenchmarkRunner(
            dataset_dir=dataset_dir,
            metadata_file=metadata_file,
            profile="flask",
        )
        records = [r for r in runner.run() if r.tool == "SecureFlow"]
        assert records
        assert all(r.prediction == r.ground_truth for r in records)


def test_project_scanner_detects_multifile_flask_sqli():
    from analyzer.project_scanner import ProjectScanner
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "routes.py").write_text(
            'from flask import request\n'
            'from repository import query_user\n'
            '\n'
            'def search():\n'
            '    name = request.args.get("name")\n'
            '    return query_user(name)\n'
        )
        (root / "repository.py").write_text(
            'def query_user(name):\n'
            '    query = "SELECT * FROM users WHERE name = " + name\n'
            '    return db.session.execute(query)\n'
        )

        result = ProjectScanner(root).scan()

        assert result.files_total == 2
        assert result.files_with_errors == 0
        assert result.findings
        assert result.findings[0].rule_id == "PY.FLASK.SQLI"


def test_project_scanner_python_ast_frontend_handles_real_flask_syntax():
    from analyzer.project_scanner import ProjectScanner
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text(
            'from flask import request\n'
            'from contextlib import closing\n'
            '\n'
            'def search() -> object:\n'
            '    try:\n'
            '        user: str = request.args.get("user")\n'
            '        with closing(get_cursor()) as cursor:\n'
            '            query = "SELECT * FROM users WHERE name = " + user\n'
            '            return cursor.execute(query)\n'
            '    except Exception as exc:\n'
            '        raise exc\n'
        )

        result = ProjectScanner(root, frontend="python-ast").scan()

        assert result.frontend == "python-ast"
        assert result.files_with_errors == 0
        assert result.findings


def test_project_scanner_accepts_multifile_parameterized_query():
    from analyzer.project_scanner import ProjectScanner
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "routes.py").write_text(
            'from flask import request\n'
            'from repository import query_user\n'
            '\n'
            'def search():\n'
            '    name = request.form.get("name")\n'
            '    return query_user(name)\n'
        )
        (root / "repository.py").write_text(
            'def query_user(name):\n'
            '    return cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
        )

        result = ProjectScanner(root).scan()

        assert result.files_total == 2
        assert result.files_with_errors == 0
        assert not result.findings


def test_secureflow_scan_sarif_contains_findings():
    from tools.secureflow_scan import _sarif
    from analyzer.project_scanner import ProjectScanner
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text(
            'from flask import request\n'
            '\n'
            'def search():\n'
            '    name = request.args.get("name")\n'
            '    cursor.execute("SELECT * FROM users WHERE name = " + name)\n'
        )

        result = ProjectScanner(root).scan()
        sarif = _sarif(result)

        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"]


def test_secureflow_scan_text_report_explains_vulnerable_flow():
    from analyzer.project_scanner import ProjectScanner
    from tools.secureflow_scan import _text_report
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text(
            'from flask import request\n'
            '\n'
            'def search():\n'
            '    name = request.args.get("name")\n'
            '    cursor.execute("SELECT * FROM users WHERE name = " + name)\n'
        )

        report = _text_report(ProjectScanner(root).scan())

        assert "SE DETECTO 1 VULNERABILIDAD" in report
        assert "request.args.get ->" in report
        assert "-> cursor.execute" in report
        assert "app.py:5 (search())" in report


def test_secureflow_scan_text_report_explains_safe_result():
    from analyzer.project_scanner import ProjectScanner
    from tools.secureflow_scan import _text_report
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text(
            'from flask import request\n'
            '\n'
            'def search():\n'
            '    name = request.args.get("name")\n'
            '    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
        )

        report = _text_report(ProjectScanner(root).scan())

        assert "NO SE DETECTARON VULNERABILIDADES" in report
        assert "No hubo errores, nodos ignorados ni llamadas internas sin enlace" in report


def test_benchmark_runner_writes_json_files():
    from tools.benchmark_runner import BenchmarkRunner
    with tempfile.TemporaryDirectory() as tmp:
        ds_dir, meta_file = _setup_benchmark(tmp, 10)
        import os
        os.chdir(tmp)
        runner = BenchmarkRunner(dataset_dir=ds_dir, metadata_file=meta_file)
        records = runner.run()
        runner.write_results(records)
        assert Path(tmp + "/benchmark_results.json").exists()
        assert not Path(tmp + "/bandit_comparison.json").exists()
        assert not Path(tmp + "/semgrep_comparison.json").exists()
        assert not Path(tmp + "/pysa_comparison.json").exists()


# =========================================== Performance evaluator (Part G)

def test_performance_evaluator_returns_results_per_batch():
    from tools.performance_evaluator import PerformanceEvaluator
    with tempfile.TemporaryDirectory() as tmp:
        _setup_benchmark(tmp, 20)
        ev = PerformanceEvaluator(dataset_dir=tmp + "/dataset")
        results = ev.evaluate(batch_sizes=[10, 20])
        assert len(results) == 2
        assert results[0].batch_size == 10
        assert results[1].batch_size == 20


def test_performance_evaluator_timings_are_positive():
    from tools.performance_evaluator import PerformanceEvaluator
    with tempfile.TemporaryDirectory() as tmp:
        _setup_benchmark(tmp, 10)
        ev = PerformanceEvaluator(dataset_dir=tmp + "/dataset")
        results = ev.evaluate(batch_sizes=[5])
        r = results[0]
        assert r.avg_total_ms >= 0
        assert r.peak_memory_kb >= 0
        assert r.avg_stage.lexer_ms >= 0
        assert r.avg_stage.taint_ms >= 0


def test_performance_evaluator_writes_report():
    from tools.performance_evaluator import PerformanceEvaluator
    with tempfile.TemporaryDirectory() as tmp:
        import os
        _setup_benchmark(tmp, 10)
        os.chdir(tmp)
        ev = PerformanceEvaluator(dataset_dir=tmp + "/dataset")
        results = ev.evaluate(batch_sizes=[5])
        ev.write_report(results)
        data = json.loads(Path(tmp + "/performance_report.json").read_text())
        assert len(data) == 1
        assert "batch_size" in data[0]
        assert "avg_stage" in data[0]
