"""Sprint 7 - Part G: Pipeline performance evaluation.

Times each stage of the SecureFlow analysis pipeline across dataset
batches of increasing size and writes performance_report.json.
"""

from __future__ import annotations

import json
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path

from analyzer.cfg_builder import build_cfg
from analyzer.ir_generator import generate_ir
from analyzer.lexer import Lexer, tokenize as _lex_tokenize
from analyzer.parser import Parser, parse
from analyzer.semantic import analyze as analyze_semantic
from analyzer.taint_engine import analyze_cfg


@dataclass
class StageTimings:
    lexer_ms: float
    parser_ms: float
    semantic_ms: float
    ir_ms: float
    cfg_ms: float
    taint_ms: float
    total_ms: float


@dataclass
class BatchResult:
    batch_size: int
    avg_total_ms: float
    avg_stage: StageTimings
    peak_memory_kb: float


def _time_pipeline(source: str) -> StageTimings:
    t = time.perf_counter

    t0 = t()
    tokens = _lex_tokenize(source)
    lexer_ms = (t() - t0) * 1000

    t0 = t()
    parser = Parser(tokens)
    program = parser.parse()
    parser_ms = (t() - t0) * 1000

    t0 = t()
    analyze_semantic(program)
    sem_ms = (t() - t0) * 1000

    t0 = t()
    module = generate_ir(program)
    ir_ms = (t() - t0) * 1000

    t0 = t()
    cfg = build_cfg(module.main.instructions)
    cfg_ms = (t() - t0) * 1000

    t0 = t()
    analyze_cfg(cfg)
    taint_ms = (t() - t0) * 1000

    total = lexer_ms + parser_ms + sem_ms + ir_ms + cfg_ms + taint_ms
    return StageTimings(
        lexer_ms=round(lexer_ms, 4),
        parser_ms=round(parser_ms, 4),
        semantic_ms=round(sem_ms, 4),
        ir_ms=round(ir_ms, 4),
        cfg_ms=round(cfg_ms, 4),
        taint_ms=round(taint_ms, 4),
        total_ms=round(total, 4),
    )


def _avg_timings(timings: list[StageTimings]) -> StageTimings:
    n = len(timings)
    return StageTimings(
        lexer_ms=round(sum(t.lexer_ms for t in timings) / n, 4),
        parser_ms=round(sum(t.parser_ms for t in timings) / n, 4),
        semantic_ms=round(sum(t.semantic_ms for t in timings) / n, 4),
        ir_ms=round(sum(t.ir_ms for t in timings) / n, 4),
        cfg_ms=round(sum(t.cfg_ms for t in timings) / n, 4),
        taint_ms=round(sum(t.taint_ms for t in timings) / n, 4),
        total_ms=round(sum(t.total_ms for t in timings) / n, 4),
    )


class PerformanceEvaluator:
    def __init__(self, dataset_dir: str = "dataset") -> None:
        self.dataset_dir = Path(dataset_dir)

    def evaluate(self, batch_sizes: list[int] | None = None) -> list[BatchResult]:
        if batch_sizes is None:
            batch_sizes = [50, 100, 250, 500, 1000]

        files = sorted(self.dataset_dir.glob("*.py"))
        if not files:
            raise FileNotFoundError(f"No programs found in {self.dataset_dir}")

        results: list[BatchResult] = []
        for size in batch_sizes:
            # Cycle through available files to reach the required batch size
            batch = [files[i % len(files)] for i in range(size)]

            tracemalloc.start()
            timings: list[StageTimings] = []
            for fp in batch:
                try:
                    timings.append(_time_pipeline(fp.read_text()))
                except Exception:
                    pass
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            if not timings:
                continue

            results.append(BatchResult(
                batch_size=size,
                avg_total_ms=round(sum(t.total_ms for t in timings) / len(timings), 4),
                avg_stage=_avg_timings(timings),
                peak_memory_kb=round(peak / 1024, 2),
            ))
        return results

    def write_report(self, results: list[BatchResult]) -> None:
        data = [asdict(r) for r in results]
        Path("performance_report.json").write_text(json.dumps(data, indent=2))


def main() -> None:
    ev = PerformanceEvaluator()
    print("Evaluating pipeline performance...")
    results = ev.evaluate()
    ev.write_report(results)
    for r in results:
        print(f"  batch={r.batch_size:>5}  avg_total={r.avg_total_ms:.4f} ms  peak_mem={r.peak_memory_kb:.1f} KB")
    print("Output: performance_report.json")


if __name__ == "__main__":
    main()
