SHELL := /bin/bash

.PHONY: help setup api web dev test lint fmt contracts clean \
        lab-build lab-up lab-down lab-reset lab-logs lab-check lab-probe \
        lab-smoke lab-samples plc-reset lab-disk lab-prune \
        ingest-live ingest-replay ingest-file db-reset \
        benign-run attack-run capture-benign capture-attack captures-all captures-validate \
        train-baselines detect-replay detector-eval \
        guard-eval budget-calibrate incident-eval detect-correlate-replay \
        demo-preflight demo-reset demo-attack \
        ablation metrics organizer-test eval-full \
        eval eval-benchmark eval-validate \
        summary-injection-live demo-warm-summaries measure-latency

help: ## Show available Makefile commands
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup: ## Install backend (uv sync) and frontend (pnpm install) dependencies
	uv sync --all-packages
	if [ -d "apps/web" ] && [ -f "apps/web/package.json" ]; then cd apps/web && pnpm install; fi

api: ## Run FastAPI backend with auto-reload on port 8000
	uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 --app-dir services/api

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

db-reset: ## Wipe and re-initialize SentinelX SQLite database and checkpoints
	rm -f data/sentinelx.db data/sentinelx.db-wal data/sentinelx.db-shm
	uv run python -c "from sentinelx.store.sqlite import init_db; init_db('data/sentinelx.db')"

ingest-live: ## Start SentinelX API with live telemetry ingestion from data/logs
	SENTINELX_INGEST_MODE=live uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 --app-dir services/api

DIR ?= data/logs
SPEED ?= 50
ingest-replay: ## Replay telemetry from DIR at SPEED factor (default 50x)
	SENTINELX_INGEST_MODE=replay SENTINELX_LOG_ROOT=$(DIR) SENTINELX_REPLAY_SPEED=$(SPEED) uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 --app-dir services/api

ingest-file: ## Ingest a JSON or CSV file using a YAML mapping (FILE=... MAPPING=...)
	uv run python scripts/ingest_file.py "$(FILE)" "$(MAPPING)"

# ==============================================================================
# Docker Lab Targets (Phase 1 & Phase 1.1)
# ==============================================================================
lab-build: ## Build all Docker lab images (hosts, decoys, plc-sim)
	@if [ ! -f lab/.env.local ]; then \
	  echo "Generating untracked lab/.env.local from lab/.env.example..."; \
	  cp lab/.env.example lab/.env.local; \
	  chmod 0600 lab/.env.local; \
	fi
	docker compose -f lab/compose.yml build

lab-up: ## Start all lab services in background and wait for health
	@avail_gb=$$(df -BG / | awk 'NR==2 {gsub("G",""); print $$4}'); \
	if [ "$$avail_gb" -lt 15 ]; then \
	  echo "ERROR: Free disk space ($${avail_gb}GB) is under 15 GB! Refusing to start lab."; \
	  df -h /; \
	  exit 1; \
	fi; \
	echo "Disk space pre-flight check passed:"; \
	df -h / | head -n 2
	@if [ ! -f lab/.env.local ]; then \
	  echo "Generating untracked lab/.env.local from lab/.env.example..."; \
	  cp lab/.env.example lab/.env.local; \
	  chmod 0600 lab/.env.local; \
	fi
	mkdir -p data/logs/wazuh data/logs/plc data/logs/cowrie data/logs/opencanary data/logs/zeek-it data/logs/zeek-dmz data/logs/zeek-ot
	touch data/logs/plc/decoy-plc.jsonl data/logs/cowrie/cowrie.json
	chmod 755 data/logs data/logs/plc data/logs/opencanary data/logs/zeek-it data/logs/zeek-dmz data/logs/zeek-ot
	# Wazuh manager and Cowrie run as non-root UID 999.
	# Preserve container ownership when directories are already writable.
	@for dir in data/logs/wazuh data/logs/cowrie; do \
		if [ "$$(stat -c %a "$$dir")" != "777" ] && [ -O "$$dir" ]; then \
			chmod 777 "$$dir"; \
		fi; \
	done
	chmod 666 data/logs/plc/decoy-plc.jsonl 2>/dev/null || true
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
	$(MAKE) lab-up

lab-logs: ## Tail logs for a specific service (e.g., make lab-logs SERVICE=wazuh-manager)
	docker compose -f lab/compose.yml logs -f $(SERVICE)

lab-check: ## Verify telemetry freshness passively (no stimulus, threshold <= 60s)
	python3 scripts/lab_check.py

lab-probe: ## Generate explicit attack-like stimulus (DO NOT RUN DURING BENIGN CAPTURE)
	@echo "================================================================================"
	@echo " [ATTACK-LIKE TRAFFIC] Generating lab probe stimulus (DO NOT RUN DURING BENIGN)"
	@echo "================================================================================"
	@bash scripts/lab_probe.sh

lab-smoke: ## Run attack and pivot smoke tests from attacker container
	bash scripts/lab_smoke.sh

lab-samples: ## Export real telemetry samples into eval/captures/samples/
	python3 scripts/export_samples.py

plc-reset: ## Reset PLC simulator registers and physics to baseline (55% normal)
	docker exec sentinelx-eng-ws curl -s -X POST http://10.10.3.20:8080/reset

lab-disk: ## Report disk usage, container writable layers, and enforce 500 MB limit
	python3 scripts/lab_disk.py

lab-prune: ## Remove stopped containers and dangling images for this project
	docker compose -f lab/compose.yml rm -f
	docker image prune -f

# ==============================================================================
# Simulation & Capture Targets (Phase 3)
# ==============================================================================
benign-run: ## Run benign activity generator (DURATION=seconds, SPEED=compression, SEED=int)
	uv run python lab/benign/benign_loop.py $$(if [ -n "$(DURATION)" ]; then echo "--duration $(DURATION)"; fi) $$(if [ -n "$(SPEED)" ]; then echo "--sim-speed $(SPEED)"; fi) $$(if [ -n "$(SEED)" ]; then echo "--seed $(SEED)"; fi)

attack-run: ## Run attack scenario (SCENARIO=baseline|reordered|slow_burn, ATTACK_SPEED=float)
	@if [ -z "$(SCENARIO)" ]; then echo "Error: SCENARIO is required (e.g. make attack-run SCENARIO=baseline)"; exit 1; fi
	uv run python scripts/attack_runner.py "$(SCENARIO)" $$(if [ -n "$(ATTACK_SPEED)" ]; then echo "--speed $(ATTACK_SPEED)"; fi)

capture-benign: ## Capture a benign day run (SEED=seed, DURATION=seconds)
	@seed=$${SEED:-42}; \
	dur=$${DURATION:-60}; \
	uv run python eval/capture.py --category benign --name "day_$$seed" --seed "$$seed" --duration "$$dur"

capture-attack: ## Capture an attack scenario (SCENARIO=baseline|reordered|slow_burn)
	@if [ -z "$(SCENARIO)" ]; then echo "Error: SCENARIO is required (e.g. make capture-attack SCENARIO=baseline)"; exit 1; fi; \
	name=$$(if [ "$(SCENARIO)" = "baseline" ]; then echo "demo_baseline"; else echo "$(SCENARIO)"; fi); \
	uv run python eval/capture.py --category attack --name "$$name" --scenario "$(SCENARIO)"

captures-all: ## Generate full set of 8 captures (5 benign days + 3 attack scenarios) with disk checks
	uv run python scripts/generate_all_captures.py

captures-validate: ## Validate all existing captures through Phase 2 replay pipeline
	uv run python eval/validate_captures.py

# ==============================================================================
# Detection Targets (Phase 4)
# ==============================================================================
train-baselines: ## Fit behavioral baselines, isolation forest, and interaction graph models
	uv run python scripts/train_baselines.py

detect-replay: ## Replay capture telemetry through detector pipeline (DIR=... SPEED=...)
	@if [ -z "$(DIR)" ]; then echo "Error: DIR is required (e.g. make detect-replay DIR=eval/captures/attack/demo_baseline)"; exit 1; fi
	uv run python scripts/detect_replay.py "$(DIR)" --speed "$${SPEED:-max}"

detector-eval: ## Run evaluation suite across all 8 captures and print detector performance matrices
	uv run python scripts/detector_eval.py

# ==============================================================================
# Correlation, Safety Guard, and Budget Targets (Phase 5)
# ==============================================================================
guard-eval: ## Run comprehensive Response Safety Guard policy decision evaluation
	uv run python scripts/guard_eval.py

budget-calibrate: ## Run Alert Budget Controller threshold calibration across benign and attack captures
	uv run python scripts/budget_calibrate.py

incident-eval: ## Run full Incident evaluation across all 8 captures and golden step coverage
	uv run python scripts/incident_eval.py

detect-correlate-replay: ## Run ingestion, detection, and correlation together against capture (DIR=... SPEED=...)
	@if [ -z "$(DIR)" ]; then echo "Error: DIR is required (e.g. make detect-correlate-replay DIR=eval/captures/attack/demo_baseline)"; exit 1; fi
	uv run python scripts/detect_correlate_replay.py --dir "$(DIR)" --speed "$${SPEED:-max}" --check-idempotency

# ==============================================================================
# Demo Operations Targets (Phase 6)
# ==============================================================================
demo-preflight: ## Run SentinelX live demo readiness and preflight validation
	uv run python scripts/demo_preflight.py

demo-reset: ## Reset DB and PLC to fresh clean baseline state for demo
	uv run python scripts/demo_reset.py

demo-attack: ## Trigger live paced baseline attack scenario (demo_baseline)
	uv run python scripts/attack_runner.py baseline

# ==============================================================================
# Comprehensive Evaluation & Scorecard Targets (Phase 7 & Phase D)
# ==============================================================================
eval: ## Run Phase D detection evaluation harness across all captures and scenarios
	uv run python -m sentinelx.eval

eval-benchmark: ## Run Phase D load and latency benchmark with synthetic telemetry
	uv run python scripts/eval_load_benchmark.py --workload $${WORKLOAD:-normal}

eval-validate: ## Validate ground truth evaluation dataset schema and invariants
	uv run python scripts/validate_evaluation_dataset.py

ablation: ## Run 4-configuration detector ablation study across all 8 captures
	uv run python eval/ablation.py

metrics: ## Run LOO precision, recall, F1, and threshold sensitivity evaluation
	uv run python eval/metrics.py

organizer-test: ## Run robustness test against unfamiliar Windows EVTX enterprise log
	uv run python eval/organizer_test.py

eval-full: ## Run unified Phase 7 master evaluation suite and regenerate scorecard.md
	uv run python eval/eval_full.py

# ==============================================================================
# LLM Analyst Summary & Safety Targets (Phase 8)
# ==============================================================================
summary-injection-live: ## Run live prompt injection resistance test against Gemini API
	@set -a; [ -f services/api/.env.local ] && . services/api/.env.local; set +a; \
	if [ -z "$$GEMINI_API_KEY" ]; then \
	  echo "NOT RUN: GEMINI_API_KEY is not set. Set GEMINI_API_KEY in services/api/.env.local or environment to run live injection tests."; \
	else \
	  uv run pytest -s engine/tests/test_llm_summary.py -k "test_live_gemini_injection_resistance"; \
	fi

demo-warm-summaries: ## Pre-generate and cache verified analyst summaries for the 3 attack incidents
	uv run python scripts/warm_summaries.py

measure-latency: ## Measure ingestion-to-incident replay throughput and processing latency
	uv run python scripts/measure_latency.py
