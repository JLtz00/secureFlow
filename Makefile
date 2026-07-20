.PHONY: test compile benchmark performance report reproduce

PYTHON ?= python3

test:
	$(PYTHON) -m pytest

compile:
	$(PYTHON) -m py_compile analyzer/*.py demos/*.py tools/*.py tests/*.py

benchmark:
	$(PYTHON) -m tools.benchmark_runner

performance:
	$(PYTHON) -m tools.performance_evaluator

report:
	$(PYTHON) -m tools.visualizer
	$(PYTHON) -m tools.research_report

reproduce: compile benchmark performance report

