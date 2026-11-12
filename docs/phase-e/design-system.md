# SentinelX Design System & Component Guidelines

**Version:** 1.0.0 (Phase E)  
**Target Environment:** Mission-Critical Cyber-Physical IT/OT Security Operations Center (SOC)  
**Aesthetic:** Information-Dense, Dark-Themed, High-Contrast, Restrained Precision.

---

## 1. Visual Direction & Principles

1. **Information-Dense Operational Clarity:** Minimize decorative whitespace and oversized cards in favor of scannable, structured data density suited for 24/7 security monitoring.
2. **Deterministic Color Semantics:** Color is strictly reserved for meaning (severity, verdict, operational status, network zone). Decorative gradients, random saturated accents, and non-functional glows are prohibited.
3. **High Scannability & Monospace Telemetry:** Technical identifiers (IP addresses, MACs, Modbus registers, timestamps, rule IDs, hash signatures) are consistently rendered in a high-legibility monospace font stack.
4. **Transparent Provenance:** Visual indicators must clearly distinguish between *Observed Telemetry* (direct raw logs), *Inferred Hypotheses* (correlator kill-chain links, graph edges, attacker intent), and *Configured Assets* (network topology).
5. **Fail-Safe Safety Communication:** Response Safety Guard decisions (`ALLOW`, `DENY`, `NEEDS_HUMAN`) must be visually distinct, unmistakable, and explicitly reinforce that SentinelX operates in advisory mode.

---

## 2. Design Tokens

### 2.1 Surfaces & Backgrounds

| Token | CSS / Tailwind Value | Application |
| :--- | :--- | :--- |
| `surface-canvas` | `#090d16` / `bg-[#090d16]` | Base page viewport background. |
| `surface-panel` | `#0d1322` / `bg-slate-950/90` | Primary sidebar, sticky headers, modals, drawers. |
| `surface-card` | `#111827` / `bg-slate-900/70` | Standard dashboard cards, table containers, widgets. |
| `surface-hover` | `#1e293b` / `bg-slate-800/60` | Table row hover, list item hover, interactive focus. |
| `surface-subtle` | `#0f172a` / `bg-slate-900/40` | Secondary backgrounds, nested code blocks, pill tags. |

### 2.2 Borders & Dividers

| Token | Value | Application |
| :--- | :--- | :--- |
| `border-subtle` | `border-slate-800/60` | Internal dividers, inactive tabs, subtle card boundaries. |
| `border-standard` | `border-slate-800` | Standard card and table borders. |
| `border-strong` | `border-slate-700` | Active selection boundaries, input outlines, modal borders. |
| `border-focus` | `ring-2 ring-blue-500` | Keyboard focus ring on interactive elements. |

### 2.3 Semantic Severity Scale

| Severity | Badge Background | Text Color | Border Color | Dot / Indicator |
| :--- | :--- | :--- | :--- | :--- |
| **Critical** | `bg-red-950/60` | `text-red-400` | `border-red-800/80` | `bg-red-500 animate-pulse` |
| **High** | `bg-orange-950/60` | `text-orange-400` | `border-orange-800/80` | `bg-orange-500` |
| **Medium** | `bg-amber-950/60` | `text-amber-400` | `border-amber-800/80` | `bg-amber-500` |
| **Low** | `bg-blue-950/60` | `text-blue-400` | `border-blue-800/80` | `bg-blue-500` |
| **Informational**| `bg-slate-900/80` | `text-slate-300` | `border-slate-700/60` | `bg-slate-400` |

### 2.4 Response Safety Guard Verdicts

| Verdict | Surface & Border | Badge | Semantic Meaning |
| :--- | :--- | :--- | :--- |
| **ALLOW** | `bg-emerald-950/30 border-emerald-800/80` | `bg-emerald-950 text-emerald-300 border-emerald-700` | Action passed safety policies. *Advisory only: manual execution required.* |
| **NEEDS_HUMAN** | `bg-amber-950/30 border-amber-800/80` | `bg-amber-950 text-amber-300 border-amber-700` | High-impact action requires dual-control human authorization. |
| **DENY** | `bg-red-950/40 border-red-800/90` | `bg-red-950 text-red-300 border-red-700 font-bold` | Action strictly blocked by safety policy (e.g., disruptive OT isolation). Unbypassable. |

### 2.5 Network Zones & Domains

| Zone / Domain | Accent Color | Badge Style | Context |
| :--- | :--- | :--- | :--- |
| **IT Enterprise** | Sky (`#38bdf8`) | `bg-sky-950/60 text-sky-400 border-sky-800/60` | Corporate subnet `10.10.1.0/24`, file servers, jump hosts. |
| **DMZ & Decoys** | Purple (`#c084fc`) | `bg-purple-950/60 text-purple-300 border-purple-800/60` | Honeypots (`10.10.2.0/24`), Cowrie SSH, OpenCanary services. |
| **ICS / OT** | Rose (`#f43f5e`) | `bg-rose-950/60 text-rose-300 border-rose-800/60` | Process control `10.10.3.0/24`, Modbus PLCs, Engineering WS. |
| **Management** | Emerald (`#34d399`) | `bg-emerald-950/60 text-emerald-400 border-emerald-800/60` | Sensor management `10.10.9.0/24`, Wazuh manager, Zeek taps. |
| **External** | Red (`#ef4444`) | `bg-red-950/60 text-red-400 border-red-800/60` | External attacker IP (`10.10.1.5` untrusted actor). |

### 2.6 Relationship Provenance

| Relationship Type | Visual Treatment | Description |
| :--- | :--- | :--- |
| **Observed Telemetry** | Solid line (`stroke: #...`, `strokeWidth: 2`) | Directly recorded in normalized event logs with exact event ID. |
| **Inferred Relationship** | Dashed line (`strokeDasharray: "6,4"`) | Correlated by kill-chain engine or interaction graph algorithm. |
| **Configured Asset Link** | Dotted line (`strokeDasharray: "2,3"`, `opacity: 0.6`) | Pre-configured architectural network topology from asset catalog. |

---

## 3. Typography Hierarchy

| Level | Size | Weight | Tracking | Usage |
| :--- | :--- | :--- | :--- | :--- |
| **Page Title (H1)** | `text-2xl` (24px) | `font-bold` | `tracking-tight` | Top-level view header with domain icon. |
| **Section Title (H2)**| `text-lg` (18px) | `font-semibold` | `tracking-tight` | Primary card headers, major section divisions. |
| **Card Header (H3)** | `text-sm` (14px) | `font-semibold` | `uppercase tracking-wider` | Section category labels, drawer headers. |
| **Body Standard** | `text-sm` (14px) | `font-normal` | `normal` | Descriptions, summaries, table text. |
| **Metadata / Captions** | `text-xs` (12px) | `font-medium` | `normal` | Timestamps, status notes, secondary counts. |
| **Monospace Telemetry** | `font-mono text-xs` (12px) | `font-medium` | `normal` | IPs, hashes, registers, rule IDs, event IDs. |

---

## 4. Shared Reusable Component Specifications

The following standardized components form the core UI building blocks:

1. **`StatusBadge`**: Canonical indicator for engine connection (`LIVE WS`, `CONNECTING`, `OFFLINE`), ingest status (`DISPATCHING`, `IDLE`), and incident states.
2. **`SeverityBadge`**: Consistent severity rendering (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) mapping directly to `SEVERITY_THEME`.
3. **`MetricCard`**: Compact KPI card displaying numerical metrics, trend pill, label, and contextual icon.
4. **`EmptyState`**: Standardized zero-data display with contextual illustration/icon, clear description, and actionable guidance (e.g. "Clear filters" or "Run replay").
5. **`ErrorState`**: Standardized error container with retry button, specific error details, and support for fallback rendering.
6. **`LoadingState`**: Polished skeleton and spinner states that preserve layout dimensions during network requests.
7. **`ConfirmationDialog`**: Accessible modal dialog for destructive or high-impact actions (e.g. Response Guard supervisor approvals/rejections, resetting state).
8. **`EvidenceLink`**: Universal clickable chip that opens raw event or signal evidence in the global `EvidenceDrawer`.
9. **`Toast`**: Non-blocking toast notification system replacing disruptive native `alert()` calls.
10. **`PageHeader`**: Unified breadcrumb, title, subtitle, and action toolbar header present on every major view.
