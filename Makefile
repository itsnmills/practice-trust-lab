# Practice Trust Lab developer tasks.
#
# Uses uv when it is on PATH and falls back to the current python3 otherwise.
# Docker is only needed for the lab targets (lab-up, evidence, lab-down).

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

PYTHON ?= python3
UV := $(shell command -v uv 2>/dev/null)

ifeq ($(UV),)
  RUFF := $(PYTHON) -m ruff
  MYPY := $(PYTHON) -m mypy
  PYTEST := $(PYTHON) -m pytest
  SETUP := $(PYTHON) -m venv .venv && .venv/bin/python -m pip install -e ".[dev]"
else
  RUFF := uv run --no-project --with ruff ruff
  MYPY := uv run --no-project --with mypy mypy
  PYTEST := uv run --no-project --with pytest --with pytest-cov pytest
  SETUP := uv venv && uv pip install -e ".[dev]"
endif

LAB_DIRS := workstation-01 frontdesk-01 msp-jump-01 clinic-ehr samba-dc

.PHONY: help setup lint format format-check typecheck test cov render-sample \
        lab-up evidence verify lab-down clean

help: ## Show this help
	@echo "Practice Trust Lab targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

setup: ## Create .venv and install the project with dev tools
	$(SETUP)

lint: ## ruff check
	$(RUFF) check .

format: ## Apply ruff formatting
	$(RUFF) format .

format-check: ## Check ruff formatting without changing files
	$(RUFF) format --check .

typecheck: ## mypy over the collector package
	$(MYPY)

test: ## Unit tests (no Docker)
	$(PYTEST) -q

cov: ## Unit tests with branch coverage + threshold from pyproject.toml
	$(PYTEST) -q --cov --cov-branch \
	  --cov-report=term-missing --cov-report=xml:coverage.xml --cov-report=json:coverage.json

render-sample: ## Render examples/sample-snapshot.json into build/
	mkdir -p build
	$(PYTHON) evidence/render_practice_snapshot.py examples/sample-snapshot.json \
	  --out build/sample-packet.html
	@echo "packet: build/sample-packet.html"

lab-up: ## Bootstrap the Docker lab and plant the shadow-IT scenario
	./scripts/bootstrap.sh
	./scripts/seed-scenario.sh

evidence: ## Run one evidence pass and render the packet (lab must be up)
	./scripts/run-evidence.sh

verify: ## Verify the evidence ledger hash chain
	$(PYTHON) evidence/collect_practice_evidence.py --verify-ledger

lab-down: ## Stop and remove the lab containers, network, and share volume
	@for d in $(LAB_DIRS); do \
	  echo "==> $$d"; \
	  (cd "$$d" && docker compose down -v) || true; \
	done
	@docker network rm mills-lab || true
	@docker volume rm mills-lab-shares || true

clean: ## Remove build/test caches (keeps the lab and evidence)
	rm -rf build dist badges .pytest_cache .ruff_cache .mypy_cache .coverage coverage.xml coverage.json
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
