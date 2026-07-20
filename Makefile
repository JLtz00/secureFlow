.PHONY: test compile benchmark flask-dataset flask-benchmark performance report reproduce

PYTHON ?= python3

test:
	$(PYTHON) -m pytest

compile:
	$(PYTHON) -m py_compile analyzer/*.py demos/*.py tools/*.py tests/*.py

benchmark:
	$(PYTHON) -m tools.benchmark_runner

flask-dataset:
	$(PYTHON) -m tools.flask_dataset_generator

flask-benchmark: flask-dataset
	$(PYTHON) -m tools.benchmark_runner --profile flask

flask-report: flask-benchmark
	$(PYTHON) -m tools.flask_report

performance:
	$(PYTHON) -m tools.performance_evaluator

report:
	$(PYTHON) -m tools.visualizer
	$(PYTHON) -m tools.research_report

reproduce: compile benchmark performance report
