# SentinelX

SentinelX is an IT/OT threat detection and deception platform engineered for living-off-the-land attack detection across enterprise and industrial telemetry.
It reconstructs multi-stage attack chains from decoy assets and industrial control telemetry while enforcing strict alert budgeting and automated response safety.
The platform provides explainable incident graphs and real-time live analyst streaming across both IT and OT environments.

## Architecture

```
+-------------------------------------------------------------------------------+
|                             Telemetry Sources                                 |
|  [Wazuh HIDS]   [Zeek Net]   [Cowrie SSH]   [OpenCanary]   [Modbus/ICS]   ...  |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
                        +-------------------------------+
                        |       Ingest & Adapters       |
                        +---------------+---------------+
                                        |
                                        v
                        +-------------------------------+
                        |       Event Normalizer        |
                        |      (Frozen Contracts)       |
                        +---------------+---------------+
                                        |
                                        v
                        +-------------------------------+
                        |       Detection Engines       |
                        |  - Rules & Signatures         |
                        |  - Baseline Profiling         |
                        |  - Statistical Anomaly        |
                        |  - Graph Pattern Matching     |
                        |  - Deception Tripwires        |
                        +---------------+---------------+
                                        |
                                 Emits Signals
                                        |
                                        v
                        +-------------------------------+
                        | Attack Correlator & Budgeting |
                        |  - Kill-Chain Reconstruction  |
                        |  - Entity Graph Correlation   |
                        |  - Alert Budget & TTFMA       |
                        +---------------+---------------+
                                        |
                                Produces Incidents
                                        |
                                        v
                        +-------------------------------+
                        |   Response Safety & Guard     |
                        |  - OT Safety Interlocks       |
                        |  - Asset Criticality Checks   |
                        |  - Human-in-the-Loop Policies |
                        +---------------+---------------+
                                        |
                                        v
                 +----------------------+----------------------+
                 |                                             |
                 v                                             v
  +-------------------------------+             +-------------------------------+
  |   SentinelX API (FastAPI)     |             |   SentinelX Web UI (Next.js)  |
  |   - REST / Events / Health    | <=========> |   - Real-time Live Feed       |
  |   - WebSocket Stream (/ws)    |             |   - Incident Command Center   |
  +-------------------------------+             +-------------------------------+
```

## Architectural Rule
**Engine Isolation:** The core engine (`engine/`) must **NEVER** import `fastapi`, `starlette`, or any web-related dependencies. Web services (`services/api`) consume `sentinelx` as a workspace dependency.

## Repository Map

```
sentinelx/
├── apps/web/                    # Next.js 15 App Router frontend (TypeScript, Tailwind, shadcn/ui)
├── services/api/                # FastAPI backend service (REST + WebSockets)
├── engine/                      # Core SentinelX library (schemas, store, ingest, detect, correlate, guard)
├── packages/contracts/          # Exported JSON Schemas and generated TypeScript types
├── content/                     # Detection rules, guard policies, and MITRE ATT&CK mappings
├── lab/                         # Virtualized lab environments and test harnesses
├── eval/                        # Evaluation scenarios, network captures, and benchmark reports
├── docs/                        # Architecture, contracts, telemetry, and evaluation documentation
├── scripts/                     # Operational scripts (contract export, data generation)
├── Makefile                     # Developer automation targets
└── pyproject.toml               # uv workspace configuration
```

## Quickstart

### Prerequisites
- Python 3.12+ managed via `uv`
- Node.js 18+ and `pnpm`

### 1. Setup
Install all Python workspace dependencies and frontend packages:
```bash
make setup
```

### 2. Start Services
Run the backend API and frontend web development servers:
```bash
# Terminal 1: Backend API (http://localhost:8000)
make api

# Terminal 2: Web UI (http://localhost:3000)
make web
```

Alternatively, run `make dev` to display execution instructions.

### 3. Run Tests and Linting
```bash
make test
make lint
```
