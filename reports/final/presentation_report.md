# SecureFlow Final Presentation Report

## Executive Summary

SecureFlow is evaluated in two modes: an academic compiler frontend for demonstrating lexer/parser/AST/IR/CFG phases, and a production frontend based on Python's built-in `ast` parser for broader Flask coverage. The same IR, CFG and taint engine are reused in both modes.

## Evaluation Artifacts

- Dataset: `data/flask_dataset/` and `data/flask_projects/`
- SecureFlow frontend: `python-ast`
- Real baselines: Bandit and Semgrep
- Raw baseline outputs: `reports/raw/`
- Real baseline JSON: `reports/benchmarks/real/flask_baselines.json`
- Flask benchmark JSON: `reports/benchmarks/flask/benchmark_results.json`

## Tool Versions

- Bandit: bandit 1.9.4
- SecureFlow: local source tree
- Semgrep: 1.170.0

## Real Comparison Metrics

The total row means all Flask snippets and multi-file projects evaluated for that tool. A score of 1.000 only describes this controlled corpus; it is not a claim of universal Python or SQL-injection coverage.

| Tool | Evaluation set | Status | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SecureFlow | Flask snippets | APPROXIMATED | 38 | 0 | 20 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| SecureFlow | Flask projects | OK | 4 | 0 | 4 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| SecureFlow | Total (snippets + projects) | APPROXIMATED,OK | 42 | 0 | 24 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| Bandit | Flask snippets | OK | 37 | 7 | 13 | 1 | 0.841 | 0.974 | 0.902 | 0.862 |
| Bandit | Flask projects | OK | 4 | 1 | 3 | 0 | 0.800 | 1.000 | 0.889 | 0.875 |
| Bandit | Total (snippets + projects) | OK | 41 | 8 | 16 | 1 | 0.837 | 0.976 | 0.901 | 0.864 |
| Semgrep | Flask snippets | OK | 2 | 7 | 13 | 36 | 0.222 | 0.053 | 0.085 | 0.259 |
| Semgrep | Flask projects | OK | 0 | 1 | 3 | 4 | 0.000 | 0.000 | 0.000 | 0.375 |
| Semgrep | Total (snippets + projects) | OK | 2 | 8 | 16 | 40 | 0.200 | 0.048 | 0.077 | 0.273 |

## Production Frontend Coverage

- Files parsed: 76/76
- Files with ignored constructs: 0
- Supported or conservatively approximated nodes: 100.0%
- Ignored nodes: 0
- Unlinked internal call occurrences: 15
- External API usages modeled conservatively: 12

## Mismatches To Discuss

- No SecureFlow mismatches in this controlled Flask evaluation.

## Scope Statement

SecureFlow is production-oriented for Flask SQL injection detection when run with `--frontend python-ast`. The custom parser remains part of the academic compiler pipeline, while the Python AST frontend is the path for real Python syntax coverage. Current hardening uses LibCST when available to preserve code formatting and emit diffs. Built-in database models cover Python DB-API patterns, SQLite, psycopg/psycopg2, MySQL Connector, PyMySQL, SQLAlchemy and Flask-SQLAlchemy. Project-specific APIs can be added with TOML models.

## Why Baselines Can Score Lower

- Bandit primarily recognizes suspicious SQL string construction and can report safe constructions conservatively.
- The Semgrep configuration used here contains local syntax rules and does not perform SecureFlow's project-level taint summaries.
- SecureFlow is specialized for the exact source-to-SQL-sink problem represented by this corpus; the result must not be interpreted as universal superiority.

## Threats To Validity

- The snippets and semi-real projects are curated by the SecureFlow authors, which can favor modeled patterns.
- The project corpus is still small and does not represent every ORM, driver, metaprogramming pattern or Python version.
- Ground truth is case-level; a larger study should label every individual source-to-sink flow and use independent reviewers.
- Tool configurations are reproducible but have different analysis designs and default rule coverage.

## Remaining Production Risks

- The taint model focuses on SQL injection, not every vulnerability class.
- Dynamic Python features such as monkey patching and runtime imports are not fully modeled.
- Ignored nodes and unlinked internal calls require manual review; external APIs use conservative taint propagation and are reported separately.
- Broader validation should add independently curated open-source Flask projects with fixed commits.
