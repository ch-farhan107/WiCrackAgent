.PHONY: dev install test lint format type docs run bench clean docker

PY := python3

dev:            ## dev environment: venv + editable install + dev tools
	$(PY) -m venv .venv
	.venv/bin/pip install -U pip
	.venv/bin/pip install -e ".[dev,docs]"
	@echo "→ activate with: source .venv/bin/activate"

install:        ## production install
	$(PY) -m pip install .

test:          ## run the pytest suite
	$(PY) -m pytest --cov --cov-report=term-missing

lint:          ## ruff check + format check
	$(PY) -m ruff check src tests
	$(PY) -m ruff format --check src tests

format:        ## auto-format
	$(PY) -m ruff format src tests
	$(PY) -m ruff check --fix src tests

type:          ## mypy
	$(PY) -m mypy src/wicrack

docs:          ## build docs site into site/
	$(PY) -m mkdocs build

docs-serve:    ## live docs server
	$(PY) -m mkdocs serve

run:           ## start the web console
	$(PY) -m wicrack.cli serve

bench:         ## benchmark cracking engine
	$(PY) -m wicrack.cli bench

docker:        ## build the docker image
	docker build -t wicrack:latest .

clean:
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov site
	find . -type d -name __pycache__ -exec rm -rf {} +
