# SentinelX Performance & Scalability Evaluation Methodology

## 1. Benchmarking Scope

System performance evaluation quantifies pipeline responsiveness, end-to-end processing latency, and computational efficiency under synthetic and replayed operational workloads.

Key evaluation axes include:
1. **Pipeline Latency Distributions:** Granular timing across ingestion ($L_{\text{ingest}}$), detection ($L_{\text{detect}}$), correlation ($L_{\text{corr}}$), and total end-to-end ($L_{\text{e2e}}$).
2. **Quantile Profiles:** Computing P50, P90, P95, and P99 latencies to reveal tail bottlenecks and worst-case execution times.
3. **Throughput Scaling:** Sustained throughput measured in events processed per second (EPS) and signals emitted per second.
4. **Storage Resource Footprint:** SQLite database growth, WAL frame management, and memory overhead under sustained load.

---

## 2. Experimental Setup & Harness

Performance profiling is executed using `scripts/eval_load_benchmark.py`:
- Generates parameterized synthetic workloads across heterogeneous sources (Zeek network flows, Modbus industrial commands, Sysmon process telemetry).
- Executes synchronous detector evaluation and asynchronous correlation in a production-identical isolated SQLite environment.
- Collects microsecond-precision wall-clock timestamps via `time.perf_counter()`.

```bash
uv run python scripts/eval_load_benchmark.py --count 1000
```

---

## 3. Performance Criteria & Invariants

| Metric | Target Threshold | Measured Performance | Invariant Status |
| :--- | :---: | :---: | :---: |
| **Sustained Throughput** | $\ge 100\text{ EPS}$ | **182.0 EPS** | **PASS** |
| **P50 End-to-End Latency** | $\le 15.0\text{ ms}$ | **5.27 ms** | **PASS** |
| **P95 End-to-End Latency** | $\le 50.0\text{ ms}$ | **7.75 ms** | **PASS** |
| **P99 End-to-End Latency** | $\le 100.0\text{ ms}$ | **9.58 ms** | **PASS** |
| **Max Detection Execution** | $\le 100.0\text{ ms}$ | **14.72 ms** | **PASS** |
| **Correlator Mean Latency** | $\le 10.0\text{ ms}$ | **1.67 ms** | **PASS** |

---

## 4. Scalability Invariants

1. **Sub-linear SQLite Growth:** Indexing and event storage grow predictably without unbounded memory leakages.
2. **Zero Queue Starvation:** Correlator event consumption operates non-blockingly, keeping processing times below event inter-arrival intervals.
3. **Industrial Determinism:** OT Modbus command evaluation consistently takes $< 10\text{ ms}$, ensuring industrial control anomalies are recognized immediately.

