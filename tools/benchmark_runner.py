"""Run SecureFlow against labeled internal-validation datasets.

External comparisons are intentionally excluded from this runner. Real
Bandit and Semgrep executions are handled by ``real_baseline_runner.py``.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from analyzer.cfg_builder import build_cfg
from analyzer.framework_profiles import get_profile
from analyzer.interprocedural import analyze_module
from analyzer.ir_generator import generate_ir
from analyzer.parser import Parser
from analyzer.python_ast_frontend import parse_python_ast
from analyzer.taint_engine import analyze_cfg

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_DIR = PROJECT_ROOT / "data" / "dataset"
DEFAULT_FLASK_DATASET_DIR = PROJECT_ROOT / "data" / "flask_dataset"
DEFAULT_METADATA_FILE = PROJECT_ROOT / "data" / "dataset_metadata.json"
DEFAULT_FLASK_METADATA_FILE = PROJECT_ROOT / "data" / "flask_dataset_metadata.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "reports" / "benchmarks"
DEFAULT_FLASK_OUTPUT_DIR = PROJECT_ROOT / "reports" / "benchmarks" / "flask"


@dataclass
class BenchmarkRecord:
    tool: str
    file: str
    prediction: str       # "VULNERABLE" or "SAFE"
    ground_truth: str
    execution_time_ms: float
    analysis_status: str = "OK"
    error_count: int = 0


# ---------------------------------------------------------------- SecureFlow

def _run_secureflow(
    filepath: Path,
    profile_name: str = "base",
    frontend: str = "python-ast",
) -> tuple[str, float, str, int]:
    source = filepath.read_text()
    t0 = time.perf_counter()
    status = "OK"
    error_count = 0
    try:
        profile = get_profile(profile_name)
        if frontend == "custom":
            parser = Parser.from_source(source)
            program = parser.parse()
            errors = parser.errors
        else:
            parsed = parse_python_ast(source, filename=str(filepath))
            program = parsed.program
            errors = parsed.errors
            if parsed.coverage.ignored_nodes:
                status = "PARTIAL"
                error_count = parsed.coverage.ignored_nodes
            elif parsed.coverage.approximated_nodes:
                status = "APPROXIMATED"
        if errors:
            status = "PARSE_ERROR"
            error_count = len(errors)
        module = generate_ir(program, profile=profile)
        summaries = analyze_module(module, profile=profile)
        prediction = "SAFE"
        for function in module.all_functions():
            cfg = build_cfg(function.instructions, name=function.name)
            result = analyze_cfg(cfg, summaries=summaries, profile=profile)
            if result.is_vulnerable:
                prediction = "VULNERABLE"
                break
    except Exception:
        prediction = "SAFE"
        status = "ANALYSIS_ERROR"
        error_count = 1
    elapsed = (time.perf_counter() - t0) * 1000
    return prediction, elapsed, status, error_count


# ---------------------------------------------------------------- Runner

class BenchmarkRunner:
    def __init__(
        self,
        dataset_dir: str | Path = DEFAULT_DATASET_DIR,
        metadata_file: str | Path = DEFAULT_METADATA_FILE,
        profile: str = "base",
        frontend: str = "python-ast",
    ) -> None:
        self.dataset_dir = Path(dataset_dir)
        self.metadata: list[dict] = json.loads(Path(metadata_file).read_text())
        self.profile = profile
        self.frontend = frontend

    def run(self) -> list[BenchmarkRecord]:
        records: list[BenchmarkRecord] = []

        for entry in self.metadata:
            filepath = self.dataset_dir / entry["file"]
            gt = entry["label"]
            pred, ms, status, error_count = _run_secureflow(
                filepath,
                self.profile,
                self.frontend,
            )
            records.append(
                BenchmarkRecord(
                    tool="SecureFlow",
                    file=entry["file"],
                    prediction=pred,
                    ground_truth=gt,
                    execution_time_ms=round(ms, 3),
                    analysis_status=status,
                    error_count=error_count,
                )
            )

        return records

    def write_results(self, records: list[BenchmarkRecord], output_dir: str | Path = ".") -> None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        all_data = [asdict(r) for r in records]
        (output / "benchmark_results.json").write_text(json.dumps(all_data, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SecureFlow benchmark suite.")
    parser.add_argument("--profile", default="base", choices=["base", "flask"])
    parser.add_argument("--frontend", default="python-ast", choices=["python-ast", "custom"])
    parser.add_argument("--dataset-dir", type=Path)
    parser.add_argument("--metadata-file", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    dataset_dir = args.dataset_dir
    metadata_file = args.metadata_file
    if args.profile == "flask":
        dataset_dir = dataset_dir or DEFAULT_FLASK_DATASET_DIR
        metadata_file = metadata_file or DEFAULT_FLASK_METADATA_FILE
        output_dir = args.output_dir or DEFAULT_FLASK_OUTPUT_DIR
    else:
        dataset_dir = dataset_dir or DEFAULT_DATASET_DIR
        metadata_file = metadata_file or DEFAULT_METADATA_FILE
        output_dir = args.output_dir or DEFAULT_OUTPUT_DIR

    runner = BenchmarkRunner(
        dataset_dir=dataset_dir,
        metadata_file=metadata_file,
        profile=args.profile,
        frontend=args.frontend,
    )
    print(f"Running benchmark with profile={args.profile}, frontend={args.frontend}...")
    records = runner.run()
    runner.write_results(records, output_dir)
    total = len([r for r in records if r.tool == "SecureFlow"])
    print(f"Internal validation complete — {total} files evaluated by SecureFlow")
    print(f"Outputs written to {output_dir}")


if __name__ == "__main__":
    main()
