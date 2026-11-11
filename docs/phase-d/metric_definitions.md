# SentinelX Metric Definitions & Formulas

## 1. Classification Metrics

Let $TP$, $FP$, $FN$, and $TN$ denote True Positives, False Positives, False Negatives, and True Negatives respectively.

### 1.1 Precision (Positive Predictive Value)
$$\text{Precision} = \frac{TP}{TP + FP}$$
- **Interpretation:** The proportion of generated alerts or detections that correspond to actual malicious activity.
- **Undefined Case:** If $TP + FP = 0$, Precision is undefined (`null` / `None`).

### 1.2 Recall (True Positive Rate / Sensitivity)
$$\text{Recall} = \frac{TP}{TP + FN}$$
- **Interpretation:** The proportion of actual malicious events or attack scenarios detected by the platform.
- **Undefined Case:** If $TP + FN = 0$, Recall is undefined (`null` / `None`).

### 1.3 F1-Score (Harmonic Mean)
$$F_1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$
- **Interpretation:** Balanced single-metric trade-off between detection coverage and alert noise.
- **Undefined Case:** If $\text{Precision} + \text{Recall} = 0$ or either is undefined, $F_1$ is undefined (`null` / `None`).

### 1.4 False Positive Rate (FPR / Fall-out)
$$\text{FPR} = \frac{FP}{FP + TN}$$
- **Interpretation:** The probability that a legitimate operational event or scenario is erroneously flagged as malicious.

### 1.5 False Negative Rate (FNR / Miss Rate)
$$\text{FNR} = \frac{FN}{FN + TP} = 1 - \text{Recall}$$
- **Interpretation:** The probability that an attacker action bypasses detection mechanisms.

---

## 2. Latency & Performance Metrics

### 2.1 Ingest Latency ($L_{\text{ingest}}$)
$$L_{\text{ingest}} = t_{\text{event\_normalized}} - t_{\text{log\_received}}$$
Elapsed time from log file ingestion to canonical `Event` schema instantiation.

### 2.2 Detector Processing Latency ($L_{\text{detect}}$)
$$L_{\text{detect}} = t_{\text{detector\_exit}} - t_{\text{event\_input}}$$
Execution duration across active detector engines (rules, baseline, anomaly, graph, deception) for a single canonical event.

### 2.3 Correlator Latency ($L_{\text{corr}}$)
$$L_{\text{corr}} = t_{\text{incident\_updated}} - t_{\text{signal\_emitted}}$$
Execution duration for signal entity extraction, graph clustering, risk scoring, and alert budget evaluation.

### 2.4 End-to-End Latency ($L_{\text{e2e}}$)
$$L_{\text{e2e}} = L_{\text{ingest}} + L_{\text{detect}} + L_{\text{corr}}$$
Total pipeline latency from log arrival to active incident update.

### 2.5 Time to Detect (TTD)
$$\text{TTD} = t_{\text{first\_signal\_or\_incident}} - t_{\text{first\_attacker\_action}}$$
The elapsed duration from an adversary's first action on an asset to SentinelX's first emitted signal or active incident.

---

## 3. Percentile Quantiles

For any measured metric latency vector $V = [v_1, v_2, \dots, v_n]$ sorted in ascending order:
- **P50 (Median):** Value at rank $\lceil 0.50 \times (n - 1) \rceil$.
- **P90:** Value at rank $\lceil 0.90 \times (n - 1) \rceil$.
- **P95:** Value at rank $\lceil 0.95 \times (n - 1) \rceil$.
- **P99:** Value at rank $\lceil 0.99 \times (n - 1) \rceil$.
- **Mean & Max:** Arithmetic average and maximum observed value across the distribution.

