"""Run real Bandit and Semgrep baselines on the Flask datasets."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from analyzer.metrics import evaluate

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FLASK_DATASET = PROJECT_ROOT / "data" / "flask_dataset"
FLASK_METADATA = PROJECT_ROOT / "data" / "flask_dataset_metadata.json"
FLASK_PROJECTS = PROJECT_ROOT / "data" / "flask_projects"
FLASK_PROJECTS_METADATA = PROJECT_ROOT / "data" / "flask_projects_metadata.json"
SEMGREP_RULES = PROJECT_ROOT / "rules" / "semgrep" / "flask-sqli.yml"
RAW_DIR = PROJECT_ROOT / "reports" / "raw"
OUTPUT = PROJECT_ROOT / "reports" / "benchmarks" / "real" / "flask_baselines.json"
VERSIONS_OUTPUT = PROJECT_ROOT / "reports" / "benchmarks" / "real" / "tool_versions.json"
REPORT = PROJECT_ROOT / "reports" / "real_baselines_report.md"


@dataclass
class RealBaselineRecord:
    tool: str
    dataset: str
    case: str
    prediction: str
    ground_truth: str
    execution_time_ms: float
    analysis_status: str
    raw_output_file: str | None = None
    command: str | None = None


@dataclass
class ToolRun:
    tool: str
    dataset: str
    raw: str
    elapsed_ms: float
    status: str
    raw_file: Path | None
    command: list[str] | None


def _tool_binary(tool: str) -> str | None:
    binary = shutil.which(tool)
    local_binary = PROJECT_ROOT / ".venv" / "bin" / tool
    if binary is None and local_binary.exists():
        binary = str(local_binary)
    return binary


def _run_command(command: list[str], raw_file: Path, timeout_seconds: int = 300) -> tuple[str, float, str]:
    env = os.environ.copy()
    env["HOME"] = str(PROJECT_ROOT / ".tool_home")
    env["SEMGREP_SEND_METRICS"] = "off"
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_seconds,
        )
        elapsed = (time.perf_counter() - t0) * 1000
        raw = proc.stdout if proc.stdout.strip() else proc.stderr
        status = "OK" if proc.returncode in (0, 1) else f"EXIT_{proc.returncode}"
    except subprocess.TimeoutExpired as exc:
        elapsed = (time.perf_counter() - t0) * 1000
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        raw = stdout if stdout.strip() else stderr
        status = "TIMEOUT"
    raw_file.parent.mkdir(parents=True, exist_ok=True)
    raw_file.write_text(raw)
    return raw, elapsed, status


def _run_tool(tool: str, dataset: str, path: Path) -> ToolRun:
    binary = _tool_binary(tool)
    if binary is None:
        return ToolRun(tool, dataset, "", 0.0, "TOOL_NOT_INSTALLED", None, None)

    raw_file = RAW_DIR / tool / f"{dataset}.json"
    if tool == "bandit":
        command = [binary, "-r", str(path), "-f", "json", "-q"]
    else:
        command = [
            binary,
            "scan",
            "--quiet",
            "--no-git-ignore",
            "--metrics",
            "off",
            "--config",
            str(SEMGREP_RULES),
            "--json",
            str(path),
        ]

    raw, elapsed, status = _run_command(command, raw_file)
    return ToolRun(tool, dataset, raw, round(elapsed, 3), status, raw_file, command)


def _bandit_findings(raw: str) -> set[str]:
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return set()
    findings: set[str] = set()
    for item in data.get("results", []):
        text = " ".join([
            str(item.get("test_id", "")),
            str(item.get("test_name", "")),
            str(item.get("issue_text", "")),
        ]).lower()
        if "sql" in text or "injection" in text or "b608" in text:
            findings.add(_normalize_path(item.get("filename", "")))
    return findings


def _semgrep_findings(raw: str) -> set[str]:
    try:
        data = json.loads(_json_payload(raw))
    except json.JSONDecodeError:
        return set()
    return {
        _normalize_path(item.get("path", ""))
        for item in data.get("results", [])
    }


def _normalize_path(path: str) -> str:
    if not path:
        return ""
    p = Path(path)
    try:
        return str(p.resolve().relative_to(PROJECT_ROOT))
    except (OSError, ValueError):
        return str(p)


def _json_payload(raw: str) -> str:
    stripped = raw.strip()
    if stripped.startswith("{"):
        return stripped
    marker = stripped.find('{"version"')
    if marker >= 0:
        return stripped[marker:]
    marker = stripped.find("{")
    return stripped[marker:] if marker >= 0 else "{}"


def _prediction_for_case(findings: set[str], dataset: str, case: str) -> str:
    if dataset == "flask_snippet":
        target = f"data/flask_dataset/{case}"
        return "VULNERABLE" if any(path.endswith(target) or path == target for path in findings) else "SAFE"
    prefix = f"data/flask_projects/{case}/"
    return "VULNERABLE" if any(path.startswith(prefix) or f"/{prefix}" in path for path in findings) else "SAFE"


def _records_for_run(run: ToolRun, metadata: list[dict]) -> list[RealBaselineRecord]:
    if run.status == "TOOL_NOT_INSTALLED":
        findings: set[str] = set()
    elif run.tool == "bandit":
        findings = _bandit_findings(run.raw)
    else:
        findings = _semgrep_findings(run.raw)

    records: list[RealBaselineRecord] = []
    for entry in metadata:
        case = entry["file"] if run.dataset == "flask_snippet" else entry["project"]
        records.append(
            RealBaselineRecord(
                tool="Bandit" if run.tool == "bandit" else "Semgrep",
                dataset=run.dataset,
                case=case,
                prediction=_prediction_for_case(findings, run.dataset, case),
                ground_truth=entry["label"],
                execution_time_ms=run.elapsed_ms,
                analysis_status=run.status,
                raw_output_file=(
                    str(run.raw_file.relative_to(PROJECT_ROOT)) if run.raw_file else None
                ),
                command=" ".join(run.command) if run.command else None,
            )
        )
    return records


def run() -> list[RealBaselineRecord]:
    snippets = json.loads(FLASK_METADATA.read_text())
    projects = json.loads(FLASK_PROJECTS_METADATA.read_text())

    runs = [
        _run_tool("bandit", "flask_snippet", FLASK_DATASET),
        _run_tool("bandit", "flask_project", FLASK_PROJECTS),
        _run_tool("semgrep", "flask_snippet", FLASK_DATASET),
        _run_tool("semgrep", "flask_project", FLASK_PROJECTS),
    ]

    records: list[RealBaselineRecord] = []
    for tool_run in runs:
        metadata = snippets if tool_run.dataset == "flask_snippet" else projects
        records.extend(_records_for_run(tool_run, metadata))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps([asdict(record) for record in records], indent=2))
    VERSIONS_OUTPUT.write_text(json.dumps(_tool_versions(runs), indent=2))
    REPORT.write_text(format_report(records))
    return records


def _tool_versions(runs: list[ToolRun]) -> dict[str, str]:
    versions: dict[str, str] = {}
    bandit = _tool_binary("bandit")
    if bandit is not None:
        try:
            proc = subprocess.run([bandit, "--version"], capture_output=True, text=True, timeout=10)
            versions["Bandit"] = proc.stdout.splitlines()[0].strip()
        except (subprocess.SubprocessError, IndexError):
            versions["Bandit"] = "unknown"
    for run in runs:
        if run.tool == "semgrep" and run.raw:
            try:
                versions["Semgrep"] = json.loads(_json_payload(run.raw)).get("version", "unknown")
                break
            except json.JSONDecodeError:
                versions["Semgrep"] = "unknown"
    return versions


def format_report(records: list[RealBaselineRecord]) -> str:
    rows = [
        "| Tool | Evaluation set | Status | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for tool in ("Bandit", "Semgrep"):
        for dataset in ("flask_snippet", "flask_project", "total"):
            subset = [
                record for record in records
                if record.tool == tool and (dataset == "total" or record.dataset == dataset)
            ]
            statuses = ",".join(sorted({record.analysis_status for record in subset})) or "-"
            predicted = {
                f"{record.dataset}:{record.case}"
                for record in subset
                if record.prediction == "VULNERABLE"
            }
            actual = {
                f"{record.dataset}:{record.case}"
                for record in subset
                if record.ground_truth == "VULNERABLE"
            }
            universe = {f"{record.dataset}:{record.case}" for record in subset}
            cm = evaluate(predicted, actual, universe)
            label = {
                "flask_snippet": "Flask snippets",
                "flask_project": "Flask projects",
                "total": "Total (snippets + projects)",
            }[dataset]
            rows.append(
                f"| {tool} | {label} | {statuses} | {cm.tp} | {cm.fp} | {cm.tn} | {cm.fn} | "
                f"{cm.precision:.3f} | {cm.recall:.3f} | {cm.f1_score:.3f} | {cm.accuracy:.3f} |"
            )
    versions = json.loads(VERSIONS_OUTPUT.read_text()) if VERSIONS_OUTPUT.exists() else {}
    version_lines = "\n".join(
        f"- {tool}: {version}"
        for tool, version in sorted(versions.items())
    ) or "- Versions unavailable"
    return (
        "# Real Flask Baselines\n\n"
        "## Tool Versions\n\n"
        f"{version_lines}\n\n"
        "## Metrics\n\n"
        "The total row combines snippets and projects; it is not a separate dataset.\n\n"
        + "\n".join(rows)
        + "\n"
    )


def main() -> None:
    records = run()
    print(f"Real baseline records written to {OUTPUT}")
    print(f"Tool versions written to {VERSIONS_OUTPUT}")
    print(f"Real baseline report written to {REPORT}")
    print(f"Records: {len(records)}")


if __name__ == "__main__":
    main()
