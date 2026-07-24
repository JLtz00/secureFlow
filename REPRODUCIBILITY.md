# SecureFlow Reproducibility

## Environment

- Python: 3.10 or newer
- Development dependency: `pytest`
- `tools/benchmark_runner.py` ejecuta solo SecureFlow para validacion interna.
- Las comparaciones empiricas usan Bandit y Semgrep reales, instalados mediante el extra `baselines`.
- Pysa se documenta como trabajo relacionado; no se le atribuyen resultados sin ejecutarlo.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e ".[dev,prod,baselines]"
```

## Validation

```bash
make validate
make demo
make test
make compile
```

`make test` uses the dependency-free runner in `tools/run_tests.py`. To run the same tests with `pytest`, install the development extras and use `make pytest`:

```bash
python3 -m pip install -e ".[dev]"
make pytest
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
make flask-ablation
make flask-baselines-real
make flask-report
```

The Flask profile writes SecureFlow internal-validation outputs to
`reports/benchmarks/flask/`, uses `data/flask_dataset_metadata.json`, and
writes a Flask-specific report to `reports/flask_research_report.md`. Real
Bandit and Semgrep comparisons are generated separately by
`make flask-baselines-real` and `make final-report`.

To regenerate all Flask-focused artifacts:

```bash
make reproduce-flask
make final-report
```

Real baselines require Bandit and Semgrep. A local virtual environment keeps them isolated:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[prod,baselines]"
.venv/bin/python -m tools.real_baseline_runner
.venv/bin/python -m tools.final_presentation_report
```

## Frontends

- `custom`: handwritten lexer/parser for the academic compiler pipeline.
- `python-ast`: production frontend backed by CPython's parser; this is the default for `secureflow_scan`.

## Project Scanner

```bash
python3 -m tools.secureflow_scan scan data/flask_projects/project_multifile_vulnerable
python3 -m tools.secureflow_scan scan data/flask_dataset/flask_multistep_query.py
python3 -m tools.secureflow_scan scan data/flask_projects/project_multifile_vulnerable --format json
python3 -m tools.secureflow_scan scan data/flask_projects/project_multifile_vulnerable --format sarif -o reports/secureflow.sarif
python3 -m tools.secureflow_scan scan ./project --exclude tests
python3 -m tools.secureflow_scan scan ./project --models config/secureflow_models.example.toml
```

The default `text` format is intended for interactive use. Use `json` or
`sarif` for automation and CI/CD integrations.

When installed with `python3 -m pip install -e .`, the same scanner is available as:

```bash
secureflow scan data/flask_projects/project_multifile_vulnerable
```

## Production Models

The built-in Flask profile covers Python DB-API call shapes, `sqlite3`,
`psycopg`/`psycopg2`, `mysql.connector`, `PyMySQL`, SQLAlchemy and
Flask-SQLAlchemy. `config/secureflow_models.example.toml` documents how to add
project sources, sinks, sanitizers, object factories and receiver methods.

Every production scan reports supported, approximated and ignored nodes,
unlinked internal calls, and external APIs modeled with conservative taint
propagation. This telemetry is part of the reproducible result and should be
reviewed before interpreting a project as safe.
