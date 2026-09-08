PYTHON ?= python3

.PHONY: compile test

compile:
	$(PYTHON) -m compileall -q app run.py tests

test:
	$(PYTHON) -m pytest