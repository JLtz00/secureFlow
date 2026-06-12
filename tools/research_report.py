"""Sprint 7 - Part I: Research report generator.

Reads all JSON outputs and produces reports/research_report.md — a publication-ready
document with detection performance tables, execution time analysis, and
research contribution summary.
"""

from __future__ import annotations

import json
from pathlib import Path

from analyzer.metrics import ConfusionMatrix, evaluate

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BENCHMARK = PROJECT_ROOT / "reports" / "benchmarks" / "benchmark_results.json"
DEFAULT_PERFORMANCE = PROJECT_ROOT / "reports" / "performance" / "performance_report.json"
DEFAULT_METADATA = PROJECT_ROOT / "data" / "dataset_metadata.json"
DEFAULT_REPORT = PROJECT_ROOT / "reports" / "research_report.md"


def _load(path: str) -> object:
    return json.loads(Path(path).read_text())


def _cm(records: list[dict], tool: str) -> ConfusionMatrix:
    predicted = {r["file"] for r in records if r["tool"] == tool and r["prediction"] == "VULNERABLE"}
    actual    = {r["file"] for r in records if r["tool"] == tool and r["ground_truth"]  == "VULNERABLE"}
    universe  = {r["file"] for r in records if r["tool"] == tool}
    return evaluate(predicted, actual, universe)


def _avg_ms(records: list[dict], tool: str) -> float:
    times = [r["execution_time_ms"] for r in records if r["tool"] == tool]
    return sum(times) / len(times) if times else 0.0


TOOLS = ["Bandit", "Semgrep", "Pysa", "SecureFlow"]


def generate_report(
    benchmark_file: str | Path = DEFAULT_BENCHMARK,
    performance_file: str | Path = DEFAULT_PERFORMANCE,
    metadata_file: str | Path = DEFAULT_METADATA,
) -> str:
    records: list[dict] = _load(str(benchmark_file))  # type: ignore[assignment]

    try:
        perf: list[dict] = _load(str(performance_file))  # type: ignore[assignment]
        perf_available = True
    except FileNotFoundError:
        perf_available = False

    dataset_meta: list[dict] = _load(str(metadata_file))  # type: ignore[assignment]
    vuln_count = sum(1 for e in dataset_meta if e["label"] == "VULNERABLE")
    safe_count = sum(1 for e in dataset_meta if e["label"] == "SAFE")

    # ---- Table 1: Detection Performance
    t1_rows = ["| Tool       | Precision | Recall | F1    | Accuracy |",
               "|------------|-----------|--------|-------|----------|"]
    for tool in TOOLS:
        cm = _cm(records, tool)
        t1_rows.append(
            f"| {tool:<10} | {cm.precision:>9.3f} | {cm.recall:>6.3f} "
            f"| {cm.f1_score:>5.3f} | {cm.accuracy:>8.3f} |"
        )

    # ---- Table 2: Execution Time
    t2_rows = ["| Tool       | Avg Time (ms) |",
               "|------------|---------------|"]
    for tool in TOOLS:
        ms = _avg_ms(records, tool)
        t2_rows.append(f"| {tool:<10} | {ms:>13.3f} |")

    # ---- Table 3: False Positive Analysis
    t3_rows = ["| Tool       | FP  | FPR   | FNR   |",
               "|------------|-----|-------|-------|"]
    for tool in TOOLS:
        cm = _cm(records, tool)
        t3_rows.append(f"| {tool:<10} | {cm.fp:>3} | {cm.fpr:>5.3f} | {cm.fnr:>5.3f} |")

    # ---- Performance section
    perf_section = ""
    if perf_available:
        perf_rows = ["| Batch | Avg Total (ms) | Peak Memory (KB) |",
                     "|-------|----------------|------------------|"]
        for r in perf:  # type: ignore[union-attr]
            perf_rows.append(
                f"| {r['batch_size']:>5} | {r['avg_total_ms']:>14.4f} | {r['peak_memory_kb']:>16.1f} |"
            )
        perf_section = "\n## Performance Evaluation\n\n" + "\n".join(perf_rows)

    sf_cm = _cm(records, "SecureFlow")
    bandit_cm = _cm(records, "Bandit")

    report = f"""# SecureFlow: Research Evaluation Report

## Abstract

SecureFlow is a compiler-based static analysis framework for detecting SQL
injection vulnerabilities in Python programs. It implements a complete
six-phase pipeline — lexical analysis, parsing, semantic analysis, IR
generation, CFG construction, and forward dataflow taint analysis — fully
integrated within a custom compiler infrastructure.

## Dataset

- **Total programs:** {len(dataset_meta)}
- **Vulnerable:** {vuln_count} ({100*vuln_count//len(dataset_meta)}%)
- **Safe:** {safe_count} ({100*safe_count//len(dataset_meta)}%)

### Categories

| Category | Description               | Label      |
|----------|---------------------------|------------|
| A        | Direct SQL injection       | VULNERABLE |
| B        | Interprocedural injection  | VULNERABLE |
| C        | Sanitized input            | SAFE       |
| D        | Parameterized queries      | SAFE       |
| E        | Complex flow (loops, branches, aliases) | VULNERABLE |

## Table 1 — Detection Performance

{chr(10).join(t1_rows)}

## Table 2 — Execution Time

{chr(10).join(t2_rows)}

## Table 3 — False Positive Analysis

{chr(10).join(t3_rows)}
{perf_section}

## Research Contributions

1. **Interprocedural taint propagation** — function summaries track
   `returns_tainted`, `taints_arguments`, and `returns_sanitized` across
   call boundaries (Sprint 6, `analyzer/interprocedural.py`).

2. **Explainable source-to-sink traces** — every vulnerability report
   includes a step-by-step SOURCE → FLOW → SINK path with line numbers
   (`analyzer/reporter.py`).

3. **Automatic code hardening** — the hardener transforms string-concatenation
   SQL calls into parameterized queries automatically (`analyzer/hardener.py`).

4. **Competitive precision/recall** — SecureFlow achieves
   precision={sf_cm.precision:.3f}, recall={sf_cm.recall:.3f}, F1={sf_cm.f1_score:.3f}
   vs Bandit precision={bandit_cm.precision:.3f}, recall={bandit_cm.recall:.3f}.

5. **Full compiler-integrated pipeline** — all analysis phases share a unified
   IR and CFG, enabling precise dataflow reasoning unavailable to
   pattern-matching tools.

6. **Reproducible benchmark dataset** — 210 synthetic programs with JSON
   ground-truth labels across five vulnerability categories.
"""
    return report


def main() -> None:
    report = generate_report()
    DEFAULT_REPORT.write_text(report)
    print(f"Research report written to {DEFAULT_REPORT}")


if __name__ == "__main__":
    main()
