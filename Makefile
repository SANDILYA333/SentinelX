SHELL := /bin/bash
export PATH := /tmp/bin:$(HOME)/.cargo/bin:$(HOME)/.local/bin:$(PATH)
export UV_PYTHON_INSTALL_DIR ?= /tmp/uv-python

.PHONY: help setup api web dev test lint fmt contracts clean

help: ## Show available Makefile commands
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup: ## Install backend (uv sync) and frontend (pnpm install) dependencies
	uv sync --all-packages
	if [ -d "apps/web" ] && [ -f "apps/web/package.json" ]; then cd apps/web && pnpm install; fi

api: ## Run FastAPI backend with auto-reload on port 8000
	uv run uvicorn app.main:app --reload --port 8000 --app-dir services/api

web: ## Run Next.js frontend dev server on port 3000
	cd apps/web && pnpm dev --port 3000

dev: ## Display instructions to run API and Web servers in separate terminals
	@echo "Run backend in Terminal 1:"
	@echo "  make api"
	@echo ""
	@echo "Run frontend in Terminal 2:"
	@echo "  make web"

test: ## Run unit and integration test suite with pytest
	uv run pytest

lint: ## Run Python (ruff) and Frontend (next lint) linters
	uv run ruff check .
	uv run ruff format --check .
	if [ -d "apps/web" ] && [ -f "apps/web/package.json" ]; then cd apps/web && pnpm lint; fi

fmt: ## Format and auto-fix Python code using ruff
	uv run ruff format .
	uv run ruff check --fix .

contracts: ## Export JSON schemas and regenerate TypeScript contracts
	uv run python scripts/export_contracts.py
	cd apps/web && pnpm run generate:types

clean: ## Clean up build artifacts, cache directories, and test databases
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type d -name ".next" -exec rm -rf {} +
	rm -rf data/*.db data/*.db-wal data/*.db-shm
