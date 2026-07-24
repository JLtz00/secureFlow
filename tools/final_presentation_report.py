"""Generate the final presentation report from real evaluation artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from analyzer.metrics import ConfusionMatrix, evaluate
from analyzer.project_scanner import ProjectScanner

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FLASK_BENCHMARK = PROJECT_ROOT / "reports" / "benchmarks" / "flask" / "benchmark_results.json"
REAL_BASELINES = PROJECT_ROOT / "reports" / "benchmarks" / "real" / "flask_baselines.json"
TOOL_VERSIONS = PROJECT_ROOT / "reports" / "benchmarks" / "real" / "tool_versions.json"
PROJECTS_METADATA = PROJECT_ROOT / "data" / "flask_projects_metadata.json"
PROJECTS_DIR = PROJECT_ROOT / "data" / "flask_projects"
SNIPPETS_DIR = PROJECT_ROOT / "data" / "flask_dataset"
OUTPUT = PROJECT_ROOT / "reports" / "final" / "presentation_report.md"


@dataclass(frozen=True)
class EvalRecord:
    tool: str
    dataset: str
    case: str
    prediction: str
    ground_truth: str
    status: str = "OK"


def main() -> None:
    records = _load_records()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(_format_report(records))
    print(f"Final presentation report written to {OUTPUT}")


def _load_records() -> list[EvalRecord]:
    records: list[EvalRecord] = []

    flask_rows = json.loads(FLASK_BENCHMARK.read_text())
    for row in flask_rows:
        if row["tool"] != "SecureFlow":
            continue
        records.append(
            EvalRecord(
                tool="SecureFlow",
                dataset="flask_snippet",
                case=row["file"],
                prediction=row["prediction"],
                ground_truth=row["ground_truth"],
                status=row["analysis_status"],
            )
        )

    project_meta = json.loads(PROJECTS_METADATA.read_text())
    for entry in project_meta:
        result = ProjectScanner(PROJECTS_DIR / entry["project"], frontend="python-ast").scan()
        records.append(
            EvalRecord(
                tool="SecureFlow",
                dataset="flask_project",
                case=entry["project"],
                prediction="VULNERABLE" if result.findings else "SAFE",
                ground_truth=entry["label"],
                status="OK" if result.files_with_errors == 0 else "PARSE_ERROR",
            )
        )

    real_rows = json.loads(REAL_BASELINES.read_text())
    for row in real_rows:
        records.append(
            EvalRecord(
                tool=row["tool"],
                dataset=row["dataset"],
                case=row["case"],
                prediction=row["prediction"],
                ground_truth=row["ground_truth"],
                status=row["analysis_status"],
            )
        )

    return records


def _format_report(records: list[EvalRecord]) -> str:
    versions = json.loads(TOOL_VERSIONS.read_text()) if TOOL_VERSIONS.exists() else {}
    versions["SecureFlow"] = "local source tree"
    rows = _metric_rows(records)
    issues = _miss_rows(records)
    coverage = _production_coverage()

    return (
        "# SecureFlow Final Presentation Report\n\n"
        "## Executive Summary\n\n"
        "SecureFlow is evaluated in two modes: an academic compiler frontend for "
        "demonstrating lexer/parser/AST/IR/CFG phases, and a production frontend "
        "based on Python's built-in `ast` parser for broader Flask coverage. The "
        "same IR, CFG and taint engine are reused in both modes.\n\n"
        "## Evaluation Artifacts\n\n"
        "- Dataset: `data/flask_dataset/` and `data/flask_projects/`\n"
        "- SecureFlow frontend: `python-ast`\n"
        "- Real baselines: Bandit and Semgrep\n"
        "- Raw baseline outputs: `reports/raw/`\n"
        "- Real baseline JSON: `reports/benchmarks/real/flask_baselines.json`\n"
        "- Flask benchmark JSON: `reports/benchmarks/flask/benchmark_results.json`\n\n"
        "## Tool Versions\n\n"
        + "\n".join(f"- {tool}: {version}" for tool, version in sorted(versions.items()))
        + "\n\n"
        "## Real Comparison Metrics\n\n"
        "The total row means all Flask snippets and multi-file projects evaluated "
        "for that tool. A score of 1.000 only describes this controlled corpus; it "
        "is not a claim of universal Python or SQL-injection coverage.\n\n"
        "| Tool | Evaluation set | Status | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |\n"
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n"
        + "\n".join(rows)
        + "\n\n"
        "## Production Frontend Coverage\n\n"
        f"- Files parsed: {coverage['files_analyzed']}/{coverage['files_total']}\n"
        f"- Files with ignored constructs: {coverage['files_partial']}\n"
        f"- Supported or conservatively approximated nodes: {coverage['coverage_ratio']:.1%}\n"
        f"- Ignored nodes: {coverage['nodes_ignored']}\n"
        f"- Unlinked internal call occurrences: {coverage['unresolved_calls']}\n"
        f"- External API usages modeled conservatively: {coverage['conservative_calls']}\n\n"
        "## Mismatches To Discuss\n\n"
        + (("\n".join(issues)) if issues else "- No SecureFlow mismatches in this controlled Flask evaluation.")
        + "\n\n"
        "## Scope Statement\n\n"
        "SecureFlow is production-oriented for Flask SQL injection detection when "
        "run with `--frontend python-ast`. The custom parser remains part of the "
        "academic compiler pipeline, while the Python AST frontend is the path for "
        "real Python syntax coverage. Current hardening uses LibCST when available "
        "to preserve code formatting and emit diffs. Built-in database models cover "
        "Python DB-API patterns, SQLite, psycopg/psycopg2, MySQL Connector, PyMySQL, "
        "SQLAlchemy and Flask-SQLAlchemy. Project-specific APIs can be added with TOML models.\n\n"
        "## Why Baselines Can Score Lower\n\n"
        "- Bandit primarily recognizes suspicious SQL string construction and can report safe constructions conservatively.\n"
        "- The Semgrep configuration used here contains local syntax rules and does not perform SecureFlow's project-level taint summaries.\n"
        "- SecureFlow is specialized for the exact source-to-SQL-sink problem represented by this corpus; the result must not be interpreted as universal superiority.\n\n"
        "## Threats To Validity\n\n"
        "- The snippets and semi-real projects are curated by the SecureFlow authors, which can favor modeled patterns.\n"
        "- The project corpus is still small and does not represent every ORM, driver, metaprogramming pattern or Python version.\n"
        "- Ground truth is case-level; a larger study should label every individual source-to-sink flow and use independent reviewers.\n"
        "- Tool configurations are reproducible but have different analysis designs and default rule coverage.\n\n"
        "## Remaining Production Risks\n\n"
        "- The taint model focuses on SQL injection, not every vulnerability class.\n"
        "- Dynamic Python features such as monkey patching and runtime imports are not fully modeled.\n"
        "- Ignored nodes and unlinked internal calls require manual review; external APIs use conservative taint propagation and are reported separately.\n"
        "- Broader validation should add independently curated open-source Flask projects with fixed commits.\n"
    )


def _metric_rows(records: list[EvalRecord]) -> list[str]:
    rows: list[str] = []
    for tool in ("SecureFlow", "Bandit", "Semgrep"):
        for dataset in ("flask_snippet", "flask_project", "total"):
            subset = [
                record for record in records
                if record.tool == tool and (dataset == "total" or record.dataset == dataset)
            ]
            if not subset:
                continue
            cm = _confusion(subset)
            statuses = ",".join(sorted({record.status for record in subset}))
            label = {
                "flask_snippet": "Flask snippets",
                "flask_project": "Flask projects",
                "total": "Total (snippets + projects)",
            }[dataset]
            rows.append(
                f"| {tool} | {label} | {statuses} | {cm.tp} | {cm.fp} | {cm.tn} | {cm.fn} | "
                f"{cm.precision:.3f} | {cm.recall:.3f} | {cm.f1_score:.3f} | {cm.accuracy:.3f} |"
            )
    return rows


def _miss_rows(records: list[EvalRecord]) -> list[str]:
    rows = []
    for record in records:
        if record.tool == "SecureFlow" and record.prediction != record.ground_truth:
            rows.append(
                f"- {record.dataset}/{record.case}: predicted {record.prediction}, "
                f"expected {record.ground_truth}, status {record.status}"
            )
    return rows


def _confusion(records: list[EvalRecord]) -> ConfusionMatrix:
    predicted = {
        f"{record.dataset}:{record.case}"
        for record in records
        if record.prediction == "VULNERABLE"
    }
    actual = {
        f"{record.dataset}:{record.case}"
        for record in records
        if record.ground_truth == "VULNERABLE"
    }
    universe = {f"{record.dataset}:{record.case}" for record in records}
    return evaluate(predicted, actual, universe)


def _production_coverage() -> dict[str, int | float]:
    totals: dict[str, int | float] = {
        "files_total": 0,
        "files_analyzed": 0,
        "files_partial": 0,
        "nodes_total": 0,
        "nodes_supported": 0,
        "nodes_approximated": 0,
        "nodes_ignored": 0,
        "unresolved_calls": 0,
        "conservative_calls": 0,
    }
    scan_targets = [
        *(SNIPPETS_DIR / row["file"] for row in json.loads((PROJECT_ROOT / "data" / "flask_dataset_metadata.json").read_text())),
        *(PROJECTS_DIR / row["project"] for row in json.loads(PROJECTS_METADATA.read_text())),
    ]
    for target in scan_targets:
        result = ProjectScanner(target, frontend="python-ast").scan()
        for key in totals:
            totals[key] += getattr(result, key)
    nodes_total = int(totals["nodes_total"])
    modeled = int(totals["nodes_supported"]) + int(totals["nodes_approximated"])
    totals["coverage_ratio"] = modeled / nodes_total if nodes_total else 1.0
    return totals


if __name__ == "__main__":
    main()
