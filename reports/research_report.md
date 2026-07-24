# SecureFlow: Internal Validation Report

## Abstract

SecureFlow is a compiler-based static analysis framework for detecting SQL
injection vulnerabilities in Python programs. It implements a complete
six-phase pipeline — lexical analysis, parsing, semantic analysis, IR
generation, CFG construction, and forward dataflow taint analysis — fully
integrated within a custom compiler infrastructure.

## Dataset

- **Total programs:** 210
- **Vulnerable:** 126 (60%)
- **Safe:** 84 (40%)

### Categories

| Category | Description               | Label      |
|----------|---------------------------|------------|
| A        | Direct SQL injection       | VULNERABLE |
| B        | Interprocedural injection  | VULNERABLE |
| C        | Sanitized input            | SAFE       |
| D        | Parameterized queries      | SAFE       |
| E        | Complex flow (loops, branches, aliases) | VULNERABLE |

## Table 1 — SecureFlow Detection Performance

| Tool       | Precision | Recall | F1    | Accuracy |
|------------|-----------|--------|-------|----------|
| SecureFlow |     1.000 |  1.000 | 1.000 |    1.000 |

## Table 2 — Execution Time

| Tool       | Avg Time (ms) |
|------------|---------------|
| SecureFlow |         0.102 |

## Table 3 — False Positive Analysis

| Tool       | FP  | FPR   | FNR   |
|------------|-----|-------|-------|
| SecureFlow |   0 | 0.000 | 0.000 |

## Performance Evaluation

| Batch | Avg Total (ms) | Peak Memory (KB) |
|-------|----------------|------------------|
|    50 |         0.7585 |             47.2 |
|   100 |         0.8995 |             65.0 |
|   250 |         0.9397 |            135.1 |
|   500 |         0.9258 |            229.0 |
|  1000 |         0.9289 |            363.0 |

## Research Contributions

1. **Interprocedural taint propagation** — function summaries track
   `returns_tainted`, `taints_arguments`, and `returns_sanitized` across
   call boundaries (Sprint 6, `analyzer/interprocedural.py`).

2. **Explainable source-to-sink traces** — every vulnerability report
   includes a step-by-step SOURCE → FLOW → SINK path with line numbers
   (`analyzer/reporter.py`).

3. **Automatic code hardening** — the hardener transforms string-concatenation
   SQL calls into parameterized queries automatically (`analyzer/hardener.py`).

4. **Measured internal-validation results** — SecureFlow achieves
   precision=1.000, recall=1.000, and
   F1=1.000 on this synthetic regression corpus. These values
   are not an external-tool comparison.

5. **Full compiler-integrated pipeline** — all analysis phases share a unified
   IR and CFG, enabling precise dataflow reasoning unavailable to
   pattern-matching tools.

6. **Reproducible benchmark dataset** — 210 synthetic programs with JSON
   ground-truth labels across five vulnerability categories.

## Comparison Scope

This report does not simulate external tools. Empirical Bandit and Semgrep
results are generated separately by `tools/real_baseline_runner.py` and
summarized in `reports/final/presentation_report.md`.
