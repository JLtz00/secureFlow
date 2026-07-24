"""Ablation study for Flask SecureFlow components."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from analyzer.cfg_builder import build_cfg
from analyzer.framework_profiles import get_profile
from analyzer.interprocedural import analyze_module
from analyzer.ir_generator import generate_ir
from analyzer.metrics import evaluate
from analyzer.project_scanner import ProjectScanner
from analyzer.python_ast_frontend import parse_python_ast
from analyzer.taint_engine import analyze_cfg

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET_DIR = PROJECT_ROOT / "data" / "flask_dataset"
DEFAULT_METADATA = PROJECT_ROOT / "data" / "flask_dataset_metadata.json"
DEFAULT_PROJECTS_DIR = PROJECT_ROOT / "data" / "flask_projects"
DEFAULT_PROJECTS_METADATA = PROJECT_ROOT / "data" / "flask_projects_metadata.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "reports" / "benchmarks" / "flask" / "ablation_results.json"
DEFAULT_REPORT = PROJECT_ROOT / "reports" / "flask_ablation_report.md"


@dataclass(frozen=True)
class AblationVariant:
    name: str
    use_interprocedural: bool
    model_parameterized_sql: bool


VARIANTS = [
    AblationVariant("full", True, True),
    AblationVariant("no_interprocedural", False, True),
    AblationVariant("no_parameterized_model", True, False),
    AblationVariant("intraprocedural_no_parameterized_model", False, False),
]


def _predict_file(path: Path, variant: AblationVariant) -> str:
    profile = get_profile("flask")
    program = parse_python_ast(path.read_text(), filename=str(path)).program
    module = generate_ir(program, profile=profile)
    summaries = analyze_module(module, profile=profile) if variant.use_interprocedural else {}
    for function in module.all_functions():
        cfg = build_cfg(function.instructions, name=function.name)
        result = analyze_cfg(
            cfg,
            summaries=summaries,
            profile=profile,
            model_parameterized_sql=variant.model_parameterized_sql,
        )
        if result.is_vulnerable:
            return "VULNERABLE"
    return "SAFE"


def run_ablation() -> list[dict]:
    metadata = json.loads(DEFAULT_METADATA.read_text())
    project_metadata = json.loads(DEFAULT_PROJECTS_METADATA.read_text())
    records: list[dict] = []

    for variant in VARIANTS:
        for entry in metadata:
            prediction = _predict_file(DEFAULT_DATASET_DIR / entry["file"], variant)
            records.append({
                "dataset": "snippet",
                "variant": variant.name,
                "case": entry["file"],
                "category": entry["category"],
                "prediction": prediction,
                "ground_truth": entry["label"],
            })

        for entry in project_metadata:
            result = ProjectScanner(
                DEFAULT_PROJECTS_DIR / entry["project"],
                use_interprocedural=variant.use_interprocedural,
                model_parameterized_sql=variant.model_parameterized_sql,
            ).scan()
            prediction = "VULNERABLE" if result.findings else "SAFE"
            records.append({
                "dataset": "project",
                "variant": variant.name,
                "case": entry["project"],
                "category": entry["category"],
                "prediction": prediction,
                "ground_truth": entry["label"],
                "files_total": result.files_total,
                "files_with_errors": result.files_with_errors,
            })

    DEFAULT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_OUTPUT.write_text(json.dumps(records, indent=2))
    DEFAULT_REPORT.write_text(format_report(records))
    return records


def format_report(records: list[dict]) -> str:
    rows = [
        "| Variant | Dataset | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for variant in [v.name for v in VARIANTS]:
        for dataset in ("snippet", "project", "combined"):
            subset = [
                r for r in records
                if r["variant"] == variant and (dataset == "combined" or r["dataset"] == dataset)
            ]
            predicted = {r["case"] for r in subset if r["prediction"] == "VULNERABLE"}
            actual = {r["case"] for r in subset if r["ground_truth"] == "VULNERABLE"}
            universe = {r["case"] for r in subset}
            cm = evaluate(predicted, actual, universe)
            rows.append(
                f"| {variant} | {dataset} | {cm.tp} | {cm.fp} | {cm.tn} | {cm.fn} | "
                f"{cm.precision:.3f} | {cm.recall:.3f} | {cm.f1_score:.3f} | {cm.accuracy:.3f} |"
            )

    return f"""# Flask Ablation Study

This study disables SecureFlow components to estimate their contribution.

- `full`: interprocedural summaries and parameterized SQL modeling enabled.
- `no_interprocedural`: function summaries disabled.
- `no_parameterized_model`: parameterized SQL safety modeling disabled.
- `intraprocedural_no_parameterized_model`: both disabled.

{chr(10).join(rows)}
"""


def main() -> None:
    records = run_ablation()
    print(f"Ablation records written to {DEFAULT_OUTPUT}")
    print(f"Ablation report written to {DEFAULT_REPORT}")
    print(f"Records: {len(records)}")


if __name__ == "__main__":
    main()
