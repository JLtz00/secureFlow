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

## Current Scope

SecureFlow now enables function-summary taint propagation in the main benchmark and models parameterized SQL calls with literal placeholders as safe when untrusted values are supplied through separate parameter arguments.

