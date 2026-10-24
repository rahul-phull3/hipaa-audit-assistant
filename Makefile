# Everyday commands. Run `make` to list them.

PYTHON ?= python3
export PYTHONPATH := src

.DEFAULT_GOAL := help
.PHONY: help install install-ui lint format test ui-typecheck ui-test ui-build e2e check demo serve eval-offline docker

help: ## List the commands
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

install: ## Install the server and its test tools into the current Python environment (editable)
	$(PYTHON) -m pip install -e ".[dev]"

install-ui: ## Install the interface's dependencies
	cd ui && npm install --no-audit --no-fund

lint: ## Check style and common mistakes in the Python code
	ruff check src tests
	ruff format --check src tests

format: ## Format the Python code and apply safe lint fixes
	ruff format src tests
	ruff check --fix src tests

test: ## Python tests (offline: no API key or network needed)
	$(PYTHON) -W error::ResourceWarning -m unittest discover -s tests -t .

ui-typecheck: ## Type-check the interface
	cd ui && npm run typecheck

ui-test: ## Interface unit tests
	cd ui && npm test

ui-build: ## Build the interface into ui/dist, where the server finds it
	cd ui && npm run build

e2e: ## Drive the built interface in a real browser against a real server (offline reviewer)
	cd ui && npm run e2e

check: lint test ui-typecheck ui-test ## Everything that runs without a browser

demo: ## Review the sample policy offline and print the report
	$(PYTHON) -m hipaa_audit audit examples/sample_policy.md --backend heuristic

serve: ## Start the server on http://127.0.0.1:8000 (settings from .env)
	$(PYTHON) -m hipaa_audit serve

eval-offline: ## Score the offline keyword matcher on synthetic policies (a regression check, not an accuracy figure)
	$(PYTHON) -m hipaa_audit eval --backend heuristic --documents 3

docker: ## Build the image and start it with docker compose
	docker compose up --build
