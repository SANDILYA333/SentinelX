SHELL := /bin/bash

.PHONY: help setup api web dev test lint fmt contracts clean \
        lab-build lab-up lab-down lab-reset lab-logs lab-check lab-smoke lab-samples

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

# ==============================================================================
# Docker Lab Targets (Phase 1)
# ==============================================================================
lab-build: ## Build all Docker lab images (hosts, decoys, plc-sim)
	docker compose -f lab/compose.yml build

lab-up: ## Start all lab services in background and wait for health
	mkdir -p data/logs/wazuh data/logs/plc data/logs/cowrie data/logs/opencanary data/logs/zeek-it data/logs/zeek-dmz data/logs/zeek-ot
	chmod -R 777 data/logs
	docker compose -f lab/compose.yml up -d
	@echo "Waiting for services to become healthy..."
	@for i in $$(seq 1 60); do \
	  unhealthy=$$(docker compose -f lab/compose.yml ps --format '{{.Service}}: {{.Health}}' | grep -E "unhealthy|starting" || true); \
	  if [ -z "$$unhealthy" ]; then \
	    echo "All monitored lab services are healthy."; \
	    break; \
	  fi; \
	  sleep 2; \
	done
	docker compose -f lab/compose.yml ps

lab-down: ## Stop all lab services and networks
	docker compose -f lab/compose.yml down

lab-reset: ## Tear down lab volumes, wipe data logs, and start fresh
	docker compose -f lab/compose.yml down -v
	docker run --rm -v $$(pwd)/data:/data debian:bookworm-slim rm -rf /data/logs 2>/dev/null || rm -rf data/logs 2>/dev/null || true
	mkdir -p data/logs/wazuh data/logs/plc data/logs/cowrie data/logs/opencanary data/logs/zeek-it data/logs/zeek-dmz data/logs/zeek-ot
	$(MAKE) lab-up

lab-logs: ## Tail logs for a specific service (e.g., make lab-logs SERVICE=wazuh-manager)
	docker compose -f lab/compose.yml logs -f $(SERVICE)

lab-check: ## Verify telemetry freshness across all 8 sources (<= 60s threshold)
	python3 scripts/lab_check.py

lab-smoke: ## Run attack and pivot smoke tests from attacker container
	bash scripts/lab_smoke.sh

lab-samples: ## Export real telemetry samples into eval/captures/samples/
	python3 scripts/export_samples.py
