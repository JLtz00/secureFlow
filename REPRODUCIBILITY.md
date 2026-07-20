# SecureFlow Reproducibility

## Environment

- Python: 3.10 or newer
- Development dependency: `pytest`
- External benchmark tools are still simulated in `tools/benchmark_runner.py`; those results must be treated as preliminary baselines.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e ".[dev]"
```

## Validation

```bash
make test
make compile
```

## Regenerate Experimental Artifacts

```bash
make reproduce
```

This command regenerates:

- `reports/benchmarks/benchmark_results.json`
- `reports/performance/performance_report.json`
- `reports/tables/*.txt`
- `reports/figures/*.csv`
- `reports/final/summary.json`
- `reports/research_report.md`

## Flask-Focused Benchmark

```bash
make flask-dataset
make flask-benchmark
make flask-report
```

The Flask profile writes its benchmark outputs to `reports/benchmarks/flask/`, uses `data/flask_dataset_metadata.json`, and writes a Flask-specific report to `reports/flask_research_report.md`.

## Project Scanner

```bash
python3 -m tools.secureflow_scan scan data/flask_projects/project_multifile_vulnerable
python3 -m tools.secureflow_scan scan data/flask_projects/project_multifile_vulnerable --format sarif -o reports/secureflow.sarif
```

When installed with `python3 -m pip install -e .`, the same scanner is available as:

```bash
secureflow scan data/flask_projects/project_multifile_vulnerable
```

## Current Scope

SecureFlow now enables function-summary taint propagation in the main benchmark, models parameterized SQL calls with literal placeholders as safe when untrusted values are supplied through separate parameter arguments, and includes a Flask-specific profile for request sources, endpoint functions, DB-API sinks, SQLAlchemy sinks, f-strings, and import aliases.
