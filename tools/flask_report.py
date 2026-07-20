"""Generate a Flask-focused benchmark report."""

from __future__ import annotations

import json
from pathlib import Path

from analyzer.metrics import evaluate
from analyzer.project_scanner import ProjectScanner

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BENCHMARK = PROJECT_ROOT / "reports" / "benchmarks" / "flask" / "benchmark_results.json"
DEFAULT_METADATA = PROJECT_ROOT / "data" / "flask_dataset_metadata.json"
DEFAULT_PROJECTS = PROJECT_ROOT / "data" / "flask_projects"
DEFAULT_PROJECTS_METADATA = PROJECT_ROOT / "data" / "flask_projects_metadata.json"
DEFAULT_REPORT = PROJECT_ROOT / "reports" / "flask_research_report.md"

TOOLS = ["SecureFlow", "Bandit", "Semgrep", "Pysa"]


def _load(path: Path) -> list[dict]:
    return json.loads(path.read_text())


def _metrics_for(records: list[dict], tool: str):
    predicted = {r["file"] for r in records if r["tool"] == tool and r["prediction"] == "VULNERABLE"}
    actual = {r["file"] for r in records if r["tool"] == tool and r["ground_truth"] == "VULNERABLE"}
    universe = {r["file"] for r in records if r["tool"] == tool}
    return evaluate(predicted, actual, universe)


def generate_report(
    benchmark_file: str | Path = DEFAULT_BENCHMARK,
    metadata_file: str | Path = DEFAULT_METADATA,
    projects_dir: str | Path = DEFAULT_PROJECTS,
    projects_metadata_file: str | Path = DEFAULT_PROJECTS_METADATA,
) -> str:
    records = _load(Path(benchmark_file))
    metadata = _load(Path(metadata_file))

    metric_rows = [
        "| Tool | Precision | Recall | F1 | Accuracy | FPR | FNR |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for tool in TOOLS:
        cm = _metrics_for(records, tool)
        metric_rows.append(
            f"| {tool} | {cm.precision:.3f} | {cm.recall:.3f} | {cm.f1_score:.3f} | "
            f"{cm.accuracy:.3f} | {cm.fpr:.3f} | {cm.fnr:.3f} |"
        )

    category_rows = [
        "| Category | Label | SecureFlow | Bandit | Semgrep | Pysa |",
        "|---|---|---|---|---|---|",
    ]
    for entry in metadata:
        preds = {
            r["tool"]: r["prediction"]
            for r in records
            if r["file"] == entry["file"]
        }
        category_rows.append(
            f"| {entry['category']} | {entry['label']} | "
            f"{preds.get('SecureFlow', '-')} | {preds.get('Bandit', '-')} | "
            f"{preds.get('Semgrep', '-')} | {preds.get('Pysa', '-')} |"
        )

    vulnerable = sum(1 for entry in metadata if entry["label"] == "VULNERABLE")
    safe = len(metadata) - vulnerable
    categories = ", ".join(sorted({entry["category"] for entry in metadata}))
    project_metadata = _load(Path(projects_metadata_file)) if Path(projects_metadata_file).exists() else []
    project_rows = [
        "| Project | Category | Label | Prediction | Files | Errors | Findings |",
        "|---|---|---|---|---:|---:|---:|",
    ]
    project_correct = 0
    for entry in project_metadata:
        result = ProjectScanner(Path(projects_dir) / entry["project"]).scan()
        prediction = "VULNERABLE" if result.findings else "SAFE"
        if prediction == entry["label"]:
            project_correct += 1
        project_rows.append(
            f"| {entry['project']} | {entry['category']} | {entry['label']} | "
            f"{prediction} | {result.files_total} | {result.files_with_errors} | "
            f"{len(result.findings)} |"
        )
    project_section = ""
    if project_metadata:
        project_section = f"""
## Multi-File Flask Projects

- Projects: {len(project_metadata)}
- Correct project-level classifications: {project_correct}/{len(project_metadata)}

{chr(10).join(project_rows)}
"""

    return f"""# Flask SQL Injection Evaluation

## Dataset

- Total Flask programs: {len(metadata)}
- Vulnerable: {vulnerable}
- Safe: {safe}
- Categories: {categories}

## Detection Metrics

{chr(10).join(metric_rows)}

## Category-Level Results

{chr(10).join(category_rows)}
{project_section}

## Scope

This Flask profile models common request sources, DB-API and SQLAlchemy raw-query sinks, import aliases, route decorators, f-strings, percent formatting, `.format()`, JSON body extraction through subscripts and `.get()`, and parameterized query patterns.
"""


def main() -> None:
    report = generate_report()
    DEFAULT_REPORT.write_text(report)
    print(f"Flask research report written to {DEFAULT_REPORT}")


if __name__ == "__main__":
    main()
