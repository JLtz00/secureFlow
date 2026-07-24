.PHONY: test pytest compile demo validate benchmark flask-dataset flask-benchmark flask-report final-report reproduce-presentation scan-demo scan-demo-file scan-demo-safe performance report reproduce

PYTHON ?= $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)

test:
	PYTHONPATH=. $(PYTHON) -m tools.run_tests

pytest:
	$(PYTHON) -m pytest

compile:
	$(PYTHON) -m py_compile analyzer/*.py demos/*.py tools/*.py tests/*.py

demo:
	PYTHONPATH=. $(PYTHON) -m demos.demo_secureflow

validate: test compile demo
	PYTHONPATH=. $(PYTHON) -m tools.secureflow_scan scan data/flask_projects/project_multifile_vulnerable

benchmark:
	$(PYTHON) -m tools.benchmark_runner

flask-dataset:
	$(PYTHON) -m tools.flask_dataset_generator

flask-benchmark: flask-dataset
	$(PYTHON) -m tools.benchmark_runner --profile flask

flask-report: flask-benchmark
	$(PYTHON) -m tools.flask_report

final-report:
	$(PYTHON) -m tools.final_presentation_report

flask-ablation: flask-dataset
	$(PYTHON) -m tools.flask_ablation

flask-baselines-real: flask-dataset
	$(PYTHON) -m tools.real_baseline_runner

reproduce-flask: flask-dataset flask-benchmark flask-ablation flask-baselines-real flask-report

reproduce-presentation: flask-dataset flask-benchmark flask-baselines-real flask-report final-report

scan-demo:
	$(PYTHON) -m tools.secureflow_scan scan data/flask_projects/project_multifile_vulnerable --format text

scan-demo-file:
	$(PYTHON) -m tools.secureflow_scan scan data/flask_dataset/flask_multistep_query.py --format text

scan-demo-safe:
	$(PYTHON) -m tools.secureflow_scan scan data/flask_projects/project_multifile_parameterized --format text

performance:
	$(PYTHON) -m tools.performance_evaluator

report:
	$(PYTHON) -m tools.visualizer
	$(PYTHON) -m tools.research_report

reproduce: compile benchmark performance report
