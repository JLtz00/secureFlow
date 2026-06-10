"""Tests for Sprint 7: dataset generator, benchmark runner, performance
evaluator, updated metrics, and visualizer."""

import json
import tempfile
from pathlib import Path

import pytest

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
    from dataset_generator import DatasetGenerator
    with tempfile.TemporaryDirectory() as tmp:
        gen = DatasetGenerator(output_dir=tmp + "/dataset")
        import os
        os.chdir(tmp)
        entries = gen.generate(210)
        assert len(entries) == 210


def test_dataset_generator_labels_are_valid():
    from dataset_generator import DatasetGenerator
    with tempfile.TemporaryDirectory() as tmp:
        import os
        os.chdir(tmp)
        gen = DatasetGenerator(output_dir=tmp + "/dataset")
        entries = gen.generate(50)
        for e in entries:
            assert e.label in ("VULNERABLE", "SAFE")
            assert e.category in ("A", "B", "C", "D", "E")


def test_dataset_generator_writes_metadata_json():
    from dataset_generator import DatasetGenerator
    with tempfile.TemporaryDirectory() as tmp:
        import os
        os.chdir(tmp)
        gen = DatasetGenerator(output_dir=tmp + "/dataset")
        gen.generate(10)
        meta = json.loads(Path(tmp + "/dataset_metadata.json").read_text())
        assert len(meta) == 10
        assert all("file" in e and "label" in e for e in meta)


def test_dataset_has_both_vulnerable_and_safe():
    from dataset_generator import DatasetGenerator
    with tempfile.TemporaryDirectory() as tmp:
        import os
        os.chdir(tmp)
        gen = DatasetGenerator(output_dir=tmp + "/dataset")
        entries = gen.generate(50)
        labels = {e.label for e in entries}
        assert "VULNERABLE" in labels
        assert "SAFE" in labels


def test_generated_programs_parse_without_error():
    from dataset_generator import DatasetGenerator
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
    from dataset_generator import DatasetGenerator
    import os
    os.chdir(tmp)
    gen = DatasetGenerator(output_dir=tmp + "/dataset")
    gen.generate(count)
    return tmp + "/dataset", tmp + "/dataset_metadata.json"


def test_benchmark_runner_returns_records_for_all_tools():
    from benchmark_runner import BenchmarkRunner
    with tempfile.TemporaryDirectory() as tmp:
        ds_dir, meta_file = _setup_benchmark(tmp, 10)
        runner = BenchmarkRunner(dataset_dir=ds_dir, metadata_file=meta_file)
        records = runner.run()
        tools = {r.tool for r in records}
        assert {"SecureFlow", "Bandit", "Semgrep", "Pysa"} == tools


def test_benchmark_runner_predictions_are_valid_labels():
    from benchmark_runner import BenchmarkRunner
    with tempfile.TemporaryDirectory() as tmp:
        ds_dir, meta_file = _setup_benchmark(tmp, 10)
        runner = BenchmarkRunner(dataset_dir=ds_dir, metadata_file=meta_file)
        records = runner.run()
        for r in records:
            assert r.prediction in ("VULNERABLE", "SAFE")


def test_benchmark_runner_secureflow_detects_direct_sqli():
    from benchmark_runner import BenchmarkRunner
    with tempfile.TemporaryDirectory() as tmp:
        ds_dir, meta_file = _setup_benchmark(tmp, 50)
        runner = BenchmarkRunner(dataset_dir=ds_dir, metadata_file=meta_file)
        records = runner.run()
        meta = json.loads(Path(meta_file).read_text())
        cat_a = {e["file"] for e in meta if e["category"] == "A"}
        sf_on_a = [r for r in records if r.tool == "SecureFlow" and r.file in cat_a]
        detected = sum(1 for r in sf_on_a if r.prediction == "VULNERABLE")
        assert detected > 0, "SecureFlow should detect some direct SQLi"


def test_benchmark_runner_writes_json_files():
    from benchmark_runner import BenchmarkRunner
    with tempfile.TemporaryDirectory() as tmp:
        ds_dir, meta_file = _setup_benchmark(tmp, 10)
        import os
        os.chdir(tmp)
        runner = BenchmarkRunner(dataset_dir=ds_dir, metadata_file=meta_file)
        records = runner.run()
        runner.write_results(records)
        assert Path(tmp + "/benchmark_results.json").exists()
        assert Path(tmp + "/bandit_comparison.json").exists()
        assert Path(tmp + "/semgrep_comparison.json").exists()
        assert Path(tmp + "/pysa_comparison.json").exists()


# =========================================== Performance evaluator (Part G)

def test_performance_evaluator_returns_results_per_batch():
    from performance_evaluator import PerformanceEvaluator
    with tempfile.TemporaryDirectory() as tmp:
        _setup_benchmark(tmp, 20)
        ev = PerformanceEvaluator(dataset_dir=tmp + "/dataset")
        results = ev.evaluate(batch_sizes=[10, 20])
        assert len(results) == 2
        assert results[0].batch_size == 10
        assert results[1].batch_size == 20


def test_performance_evaluator_timings_are_positive():
    from performance_evaluator import PerformanceEvaluator
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
    from performance_evaluator import PerformanceEvaluator
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
